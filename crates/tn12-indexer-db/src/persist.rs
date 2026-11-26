//! Translates a TN12 REST transaction into Postgres rows.
//!
//! Identity note: prefer canonical KIP-20 `covenantId` when an upstream source
//! exposes it. Fall back to the P2SH `script_hash` for legacy version-0 rows
//! and REST shapes that still omit covenant binding metadata.

mod shadow;
pub mod genesis;
pub mod identity;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use kaspa_addresses::{Address, Version};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use tn12_indexer_core::{blake2b_256, is_p2sh_script_pubkey, p2sh_script_hash, read_push};
use tn12_indexer_core::{
    compute_genesis_covenant_id_for_output, compute_genesis_covenant_id_for_outputs,
    compute_genesis_covenant_id_for_outputs_at_input, KnownTemplate, RestTransaction, RestTxOutput,
};
use tn12_indexer_decoder::{
    api_payment_channel::{self, ApiPaymentChannelAction},
    default_registry, detect_inscription_from_reveal, kaspa_fomo_round, kcc20_fee_ticket,
    kcc20_fee_v1,
    kcc20_orderbook, kcc20_snapshot_bootstrap, kcc20_snapshot_controller, kcc20_standard,
    kcc20_vesting, kcc20_wrapper, kcom_claim, kcom_vesting,
    registry::DecoderRegistry, TemplateDecoder,
};

use crate::api_payments::{
    apply_indexed_api_payment_channel_close_requested,
    apply_indexed_api_payment_channel_continuation, apply_indexed_api_payment_channel_refund,
    apply_indexed_api_payment_channel_settlement, upsert_indexed_api_payment_channel_open,
    IndexedApiPaymentChannelCloseRequested, IndexedApiPaymentChannelContinuation,
    IndexedApiPaymentChannelOpen, IndexedApiPaymentChannelRefund,
    IndexedApiPaymentChannelSettlement,
};
use crate::{claim, repo};

mod acceptance;
mod rest_replay_fence;
pub use rest_replay_fence::StaleRestAcceptance;
mod acceptance_cohort;
mod acceptance_map;
mod acceptance_map_apply;
mod acceptance_map_state;
pub use acceptance_map_apply::{
    HistoricalAcceptanceCommitNotApplied, HistoricalAcceptanceOutcome,
    HistoricalAcceptanceOutcomeUnknown,
};
mod acceptance_map_lifecycle;
mod acceptance_map_proof;
pub use acceptance_cohort::HistoricalAcceptanceCohort;
pub use acceptance_map::{
    AcceptanceWindowPending, AcceptanceEvidenceChanged,
    HistoricalAcceptanceBlock, HistoricalAcceptanceSourceProof, HistoricalAcceptanceTarget,
    HistoricalAcceptanceWindow,
};
pub use acceptance_map_lifecycle::HistoricalAcceptanceMapGuard;
pub use acceptance_map_proof::HistoricalAcceptanceMapProof;
mod consumer_fence;
mod settled_fence;
pub use settled_fence::SettledRecheckFence;
mod recovery_session;
mod recovery_impact;
mod paged_recovery;
mod chunked_recovery;
mod recovery_removal_steps;
mod recovery_summary_pages;
pub use recovery_removal_steps::RecoveryRemovalRetry;
pub use recovery_impact::{RecoveryBlockImpact, RecoveryImpactLimit, RecoveryReplanRequired};
pub use paged_recovery::{PagedRecoveryOwner, RecoveryReplayPage, StagedRecoveryBlock};
pub use recovery_session::CanonicalWriteLease;
pub use consumer_fence::{execute_fenced_metadata, DurableConsumerFence};
mod generic_bulk;
mod deferred_decode;
#[cfg(test)]
mod deferred_decode_tests;
mod live_pressure;
mod fee_trades;
#[cfg(test)]
mod replay_genesis_tests;
mod read_prefetch;
pub use acceptance::{
    AcceptanceConflict, AcceptanceEvidenceConflict, AcceptanceReconciliationStats,
    AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
    CanonicalBlockReplacement, NonEquivalentBlockEvidence,
};
pub use generic_bulk::{GenericProbeAttempt, GenericProbeOutcome, ProbeReason};

const PERSIST_WRITER_LOCK_KEY: i64 = 0x544e31324b434332;
const DEFAULT_PERSIST_LOCK_TIMEOUT: &str = "2s";
const DEFAULT_PERSIST_STATEMENT_TIMEOUT: &str = "10s";
const OPTIONAL_DEPLOY_CLAIM_LOCK_TIMEOUT: &str = "250ms";
const OPTIONAL_DEPLOY_CLAIM_STATEMENT_TIMEOUT: &str = "750ms";
const OPTIONAL_DEPLOY_CLAIM_RETRY_TIMEOUT: Duration = Duration::from_millis(750);
const OPTIONAL_CLASSIFICATION_LOCK_TIMEOUT: &str = "250ms";
const OPTIONAL_CLASSIFICATION_STATEMENT_TIMEOUT: &str = "750ms";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisStateRepairReport {
    pub txid: String,
    pub covenant_id: String,
    pub outputs_verified: usize,
    pub null_states_found: usize,
    pub states_repaired: u64,
    pub applied: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapperActionStateRepairReport {
    pub txid: String,
    pub controller_vout: i32,
    pub previous_state: Option<Value>,
    pub verified_state: Value,
    pub changed: bool,
    pub applied: bool,
}

fn ensure_wrapper_output_address(address: &str, script_hash: &[u8; 32]) -> Result<()> {
    let parsed = Address::try_from(address)
        .map_err(|_| anyhow::anyhow!("wrapper output address is invalid"))?;
    anyhow::ensure!(
        parsed.version == Version::ScriptHash && parsed.payload.as_slice() == script_hash,
        "wrapper output address disagrees with its script hash"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistTransientKind {
    WriterLockBusy,
    WriterBudgetExceeded,
    LockTimeout,
    StatementTimeout,
    DeadlockDetected,
    SerializationFailure,
    PoolTimedOut,
}

/// A generic write must return to whole-window reconciliation, never local
/// splitting or serial fallback, when its final database outcome is uncertain.
#[derive(Debug, thiserror::Error)]
#[error("{phase} generic bulk persist outcome unknown: {detail}")]
pub struct GenericWriteOutcomeUnknown {
    pub phase: &'static str,
    pub detail: String,
}

#[derive(Debug)]
pub struct TransientPersistError {
    pub kind: PersistTransientKind,
    operation: &'static str,
    message: String,
}

impl TransientPersistError {
    /// Report a writer budget failure only after rollback has been acknowledged.
    pub fn writer_budget_exceeded() -> Self {
        Self {
            kind: PersistTransientKind::WriterBudgetExceeded,
            operation: "generic bulk persist",
            message: "experimental generic writer body budget exceeded".into(),
        }
    }

    fn writer_lock_busy(operation: &'static str) -> Self {
        Self {
            kind: PersistTransientKind::WriterLockBusy,
            operation,
            message: "persist writer lock is busy".to_string(),
        }
    }

    fn from_sqlx(kind: PersistTransientKind, operation: &'static str, error: sqlx::Error) -> Self {
        Self {
            kind,
            operation,
            message: error.to_string(),
        }
    }
}

impl fmt::Display for TransientPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: transient persist pressure ({:?}): {}",
            self.operation, self.kind, self.message
        )
    }
}

impl Error for TransientPersistError {}

pub fn is_transient_persist_error(error: &anyhow::Error) -> bool {
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<GenericWriteOutcomeUnknown>().is_some())
    {
        return false;
    }
    error.chain().any(|cause| {
        cause.downcast_ref::<TransientPersistError>().is_some()
            || cause
                .downcast_ref::<sqlx::Error>()
                .and_then(transient_kind_from_sqlx)
                .is_some()
            || is_transient_persist_message(&cause.to_string())
    })
}

fn is_transient_persist_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("canceling statement due to lock timeout")
        || normalized.contains("canceling statement due to statement timeout")
        || normalized.contains("deadlock detected")
        || normalized.contains("could not serialize access")
        || normalized.contains("pool timed out")
        || normalized.contains("persist writer lock is busy")
}

fn transient_kind_from_sqlx(error: &sqlx::Error) -> Option<PersistTransientKind> {
    if matches!(error, sqlx::Error::PoolTimedOut) {
        return Some(PersistTransientKind::PoolTimedOut);
    }
    let db_error = error.as_database_error()?;
    match db_error.code().as_deref() {
        Some("55P03") => Some(PersistTransientKind::LockTimeout),
        Some("57014") => Some(PersistTransientKind::StatementTimeout),
        Some("40P01") => Some(PersistTransientKind::DeadlockDetected),
        Some("40001") => Some(PersistTransientKind::SerializationFailure),
        _ => None,
    }
}

fn classify_persist_sqlx_error(operation: &'static str, error: sqlx::Error) -> anyhow::Error {
    if let Some(kind) = transient_kind_from_sqlx(&error) {
        TransientPersistError::from_sqlx(kind, operation, error).into()
    } else {
        error.into()
    }
}

/// Put in-batch creators before their spenders, independent of REST txid order.
/// Ready transactions retain their original priority. Validate the entire graph
/// before any writes so malformed duplicate IDs or cycles cannot partially apply.
pub fn transactions_in_dependency_order(
    txs: &[RestTransaction],
) -> Result<std::borrow::Cow<'_, [RestTransaction]>> {
    use std::collections::{BTreeSet, HashMap};
    let mut by_id = HashMap::with_capacity(txs.len());
    for (index, tx) in txs.iter().enumerate() {
        if by_id
            .insert(tx.transaction_id.to_ascii_lowercase(), index)
            .is_some()
        {
            anyhow::bail!(
                "duplicate transaction id in persistence batch: {}",
                tx.transaction_id
            );
        }
    }
    let mut pending = vec![0usize; txs.len()];
    let mut children = vec![Vec::new(); txs.len()];
    for (child, tx) in txs.iter().enumerate() {
        let parents: BTreeSet<_> = tx
            .inputs
            .iter()
            .filter_map(|input| {
                by_id
                    .get(&input.previous_outpoint_hash.to_ascii_lowercase())
                    .copied()
            })
            .collect();
        pending[child] = parents.len();
        for parent in parents {
            children[parent].push(child);
        }
    }
    let mut ready: BTreeSet<_> = pending
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut order = Vec::with_capacity(txs.len());
    while let Some(index) = ready.pop_first() {
        order.push(index);
        for &child in &children[index] {
            pending[child] -= 1;
            if pending[child] == 0 {
                ready.insert(child);
            }
        }
    }
    if order.len() != txs.len() {
        anyhow::bail!("cyclic transaction dependencies in persistence batch");
    }
    if order
        .iter()
        .enumerate()
        .all(|(index, ordered)| index == *ordered)
    {
        Ok(std::borrow::Cow::Borrowed(txs))
    } else {
        Ok(std::borrow::Cow::Owned(
            order.into_iter().map(|index| txs[index].clone()).collect(),
        ))
    }
}

#[async_trait]
pub trait Persister: Send + Sync {
    fn paged_recovery_writer(&self) -> Option<&PgPersister> {
        None
    }
    /// Optional cache warming only. The ordered writer must repeat every state
    /// check inside its transaction; callers must never use this as evidence.
    async fn prefetch_identities(&self, _txids: &[String]) -> Result<bool> {
        Ok(false)
    }
    async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats>;
    async fn persist_batch(&self, txs: &[RestTransaction]) -> Result<PersistStats> {
        let txs = transactions_in_dependency_order(txs)?;
        let mut total = PersistStats::default();
        for tx in txs.iter() {
            total.merge(self.persist_tx(tx).await?);
        }
        Ok(total)
    }
    async fn revert_block(&self, block_hash: &[u8]) -> Result<RevertStats>;
    async fn reconcile_accepting_block(
        &self,
        _proof: &CanonicalBlockReplacement,
    ) -> Result<AcceptanceReconciliationStats> {
        anyhow::bail!("canonical acceptance reconciliation is unsupported by this persister")
    }
    async fn historical_acceptance_cohort(
        &self,
        _old_hashes: &[Vec<u8>],
    ) -> Result<HistoricalAcceptanceCohort> {
        anyhow::bail!("historical acceptance cohort capture is unsupported by this persister")
    }
    async fn reconcile_historical_acceptance_map(
        &self,
        _proof: &HistoricalAcceptanceMapProof,
    ) -> Result<AcceptanceReconciliationStats> {
        anyhow::bail!("historical acceptance map reconciliation is unsupported by this persister")
    }
    async fn classify_historical_acceptance_outcome(
        &self,
        _proof: &HistoricalAcceptanceMapProof,
    ) -> Result<HistoricalAcceptanceOutcome> {
        anyhow::bail!(
            "historical acceptance outcome classification is unsupported by this persister"
        )
    }
    async fn revert_blocks(&self, block_hashes: &[Vec<u8>]) -> Result<Vec<RevertStats>> {
        let mut results = Vec::with_capacity(block_hashes.len());
        for block_hash in block_hashes {
            results.push(self.revert_block(block_hash).await?);
        }
        Ok(results)
    }
    async fn has_utxo(&self, txid_hex: &str, vout: i32) -> Result<bool>;
    async fn existing_utxos(&self, outpoints: &[(String, i32)]) -> Result<HashSet<(String, i32)>> {
        let mut existing = HashSet::new();
        for (txid, vout) in outpoints {
            if self.has_utxo(txid, *vout).await? {
                existing.insert((txid.clone(), *vout));
            }
        }
        Ok(existing)
    }
    /// Find a different persisted spender of an input in a retained live intent.
    /// Recovery must verify the block against its REST source before reverting it.
    async fn conflicting_input_spends(
        &self,
        _txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        anyhow::bail!("persisted input spend lookup is unsupported by this persister")
    }
    /// All indexed transactions affected by reverting a block. Implementations
    /// must reject a block with indexed spends of outputs it created elsewhere.
    async fn indexed_block_transaction_ids(&self, _block_hash: &str) -> Result<Vec<String>> {
        anyhow::bail!("indexed block transaction lookup is unsupported by this persister")
    }
    /// Recovery-only discovery. Descendants must be journaled and checked again
    /// under the writer lock before any removal.
    async fn recovery_block_impact(&self, block_hash: &str) -> Result<RecoveryBlockImpact> {
        Ok(RecoveryBlockImpact {
            block_hash: block_hash.to_owned(),
            transaction_ids: self.indexed_block_transaction_ids(block_hash).await?,
            descendants: Vec::new(),
        })
    }
    async fn revert_recovery_blocks(&self, impacts: &[RecoveryBlockImpact]) -> Result<Vec<RevertStats>> {
        anyhow::ensure!(impacts.iter().all(|i| i.descendants.is_empty()),
            "dependent recovery removal is unsupported by this persister");
        let hashes = impacts.iter().map(|i| hex::decode(&i.block_hash)).collect::<std::result::Result<Vec<_>, _>>()?;
        self.revert_blocks(&hashes).await
    }
    /// Find an indexed transaction whose stored accepting block differs from
    /// the source acceptance in the retained live write intent.
    async fn stale_persisted_acceptances(
        &self,
        _txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        anyhow::bail!("persisted acceptance lookup is unsupported by this persister")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PersistedInputSpend {
    pub spender_txid: String,
    pub block_hash: String,
    pub block_blue_score: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PersistStats {
    pub blocks_inserted: u64,
    pub covenants_inserted: u64,
    pub utxos_inserted: u64,
    pub utxos_spent: u64,
    pub actions_inserted: u64,
}

impl PersistStats {
    pub fn merge(&mut self, other: PersistStats) {
        self.blocks_inserted += other.blocks_inserted;
        self.covenants_inserted += other.covenants_inserted;
        self.utxos_inserted += other.utxos_inserted;
        self.utxos_spent += other.utxos_spent;
        self.actions_inserted += other.actions_inserted;
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RevertStats {
    pub reverted_blue_score: Option<u64>,
    pub blocks_removed: u64,
    pub covenants_removed: u64,
    pub utxos_created_removed: u64,
    pub utxos_reactivated: u64,
    pub actions_removed: u64,
    pub covenants_unclassified: u64,
}

#[derive(Clone)]
pub struct PgPersister {
    pool: PgPool,
    decoders: DecoderRegistry,
    network_id: String,
    wait_for_writer_lock: bool,
    generic_bulk_persist: bool,
    native_genesis_bulk: bool,
    generic_bulk_max_txs: Option<usize>,
    generic_writer_budget: bool,
    historical_acceptance_hold_budget: Duration,
    consumer_fence: Option<DurableConsumerFence>,
    settled_recheck_fence: Option<SettledRecheckFence>,
    recovery_session: Option<recovery_session::RecoverySessionFence>,
    read_prefetch: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    writer_priority: live_pressure::WriterPriority,
    rest_removal_guard: Option<std::collections::BTreeMap<Vec<u8>, i64>>,
}

// One budgeted batch policy for live and repair writers. Legacy unbudgeted
// controls must not silently masquerade as an effective shared-writer setting.
fn budgeted_batch_size(setting: &impl Fn(&str) -> Option<String>) -> Result<usize> {
    anyhow::ensure!(setting("TN12_GENERIC_BULK_MAX_TXS").is_none(),
        "TN12_GENERIC_BULK_MAX_TXS is unsupported with a budgeted writer; use TN12_BUDGETED_GENERIC_BULK_MAX_TXS (16..=64)");
    let requested = setting("TN12_BUDGETED_GENERIC_BULK_MAX_TXS");
    let effective = requested
        .as_deref()
        .unwrap_or("16")
        .parse::<usize>()
        .context("invalid TN12_BUDGETED_GENERIC_BULK_MAX_TXS")?;
    anyhow::ensure!(
        (16..=64).contains(&effective),
        "TN12_BUDGETED_GENERIC_BULK_MAX_TXS must be between 16 and 64"
    );
    tracing::info!(requested = ?requested, effective, "validated budgeted writer batch policy");
    Ok(effective)
}

impl PgPersister {
    /// Replace only the controller state of an accepted wrapper action. The
    /// revealed script and the exact output script must have the same hash.
    /// Root and holder outputs are outside the write set.
    pub async fn repair_wrapper_action_state(
        &self,
        source: &RestTransaction,
        apply: bool,
    ) -> Result<WrapperActionStateRepairReport> {
        anyhow::ensure!(source.is_accepted, "wrapper action is not accepted");
        anyhow::ensure!(
            source.accepting_block_hash.is_some(),
            "wrapper action has no acceptance evidence"
        );
        let registry = default_registry();
        let mut candidates = Vec::new();
        for input in &source.inputs {
            let sig_script =
                hex::decode(&input.signature_script).context("decode wrapper signature script")?;
            let Some(reveal) = extract_last_push(&sig_script) else {
                continue;
            };
            let Some(classification) = classify_reveal(&registry, &sig_script, &reveal) else {
                continue;
            };
            if classification.template_name != "KCC20Wrapper"
                || !matches!(
                    classification.entrypoint.as_deref(),
                    Some("wrap" | "unwrap")
                )
            {
                continue;
            }
            let args = kcc20_wrapper::decode_action_args(&sig_script)?
                .context("wrapper action arguments are missing")?;
            let output_index = args
                .get("wrapperOutputIndex")
                .and_then(Value::as_str)
                .context("wrapper continuation index is missing")?
                .parse::<i32>()?;
            let output = source
                .outputs
                .iter()
                .find(|out| out.index as i32 == output_index)
                .context("wrapper continuation output is missing")?;
            let script = hex::decode(&output.script_public_key)?;
            anyhow::ensure!(
                p2sh_script_hash(&script) == Some(blake2b_256(&reveal)),
                "wrapper continuation script does not match revealed controller"
            );
            ensure_wrapper_output_address(
                output
                    .script_public_key_address
                    .as_deref()
                    .context("wrapper continuation address is missing")?,
                &blake2b_256(&reveal),
            )?;
            anyhow::ensure!(
                classification.args.is_object(),
                "wrapper constructor state could not be decoded"
            );
            candidates.push((output_index, script, classification.args));
        }
        anyhow::ensure!(
            candidates.len() == 1,
            "wrapper action must have exactly one verified controller continuation"
        );
        let (vout, script, state) = candidates.pop().unwrap();
        let txid = hex::decode(&source.transaction_id)?;
        anyhow::ensure!(txid.len() == 32, "invalid wrapper transaction id");
        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        if apply {
            self.acquire_persist_writer_lock(&mut conn).await?;
        }
        let lookup = if apply {
            "SELECT script_pubkey,state,created_block FROM covenant_utxos WHERE txid=$1 AND vout=$2 FOR UPDATE"
        } else {
            "SELECT script_pubkey,state,created_block FROM covenant_utxos WHERE txid=$1 AND vout=$2"
        };
        let (stored_script, previous_state, created_block): (Vec<u8>, Option<Value>, Vec<u8>) =
            sqlx::query_as(lookup)
                .bind(&txid)
                .bind(vout)
                .fetch_one(&mut *conn)
                .await
                .context("wrapper controller output is absent from database")?;
        anyhow::ensure!(
            stored_script == script,
            "stored wrapper controller script disagrees with accepted transaction"
        );
        anyhow::ensure!(
            source.accepting_block_hash.as_deref().and_then(|hash| hex::decode(hash).ok())
                .as_deref() == Some(created_block.as_slice()),
            "stored wrapper controller acceptance block disagrees with source"
        );
        let changed = previous_state.as_ref() != Some(&state);
        if apply && changed {
            let updated = sqlx::query(
                "UPDATE covenant_utxos SET state=$1 WHERE txid=$2 AND vout=$3 AND script_pubkey=$4 AND state IS NOT DISTINCT FROM $5",
            )
            .bind(&state)
            .bind(&txid)
            .bind(vout)
            .bind(&script)
            .bind(&previous_state)
            .execute(&mut *conn)
            .await?
            .rows_affected();
            anyhow::ensure!(updated == 1, "wrapper controller changed during repair");
            repo::mark_kcc20_projection_dirty_tx(
                &mut conn,
                "wrapper_action_state_repair",
                Some(&txid),
            )
            .await?;
        }
        conn.commit().await?;
        Ok(WrapperActionStateRepairReport {
            txid: source.transaction_id.clone(),
            controller_vout: vout,
            previous_state,
            verified_state: state,
            changed,
            applied: apply,
        })
    }

    /// Repair a pruned wrapper transaction using its persisted reveal classification.
    /// The spend action and covenant constructor were decoded from the revealed
    /// script during ingest; the continuation output must still match that
    /// classified script hash, address, and accepting block.
    pub async fn repair_wrapper_action_from_indexed_evidence(
        &self,
        transaction_id: &str,
        apply: bool,
    ) -> Result<WrapperActionStateRepairReport> {
        anyhow::ensure!(
            transaction_id.len() == 64
                && transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "repair txid must be 64 hex characters"
        );
        let txid = hex::decode(transaction_id)?;
        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        if apply {
            self.acquire_persist_writer_lock(&mut conn).await?;
        }
        let actions: Vec<(Vec<u8>, Vec<u8>, Option<Value>)> = sqlx::query_as(
            "SELECT covenant_id,block_hash,decoded_args FROM covenant_actions \
             WHERE txid=$1 AND action='spend' AND entrypoint IN ('wrap','unwrap')",
        )
        .bind(&txid)
        .fetch_all(&mut *conn)
        .await?;
        anyhow::ensure!(
            actions.len() == 1,
            "indexed repair requires exactly one classified wrapper action"
        );
        let (action_covenant_id, action_block, decoded_args) = &actions[0];
        let decoded_args = decoded_args
            .as_ref()
            .and_then(Value::as_object)
            .context("wrapper action has no decoded reveal arguments")?;
        let vout = decoded_args
            .get("wrapperOutputIndex")
            .and_then(Value::as_str)
            .context("indexed wrapper action has no continuation output index")?
            .parse::<i32>()?;
        anyhow::ensure!(vout >= 0, "invalid wrapper continuation output index");
        let lookup = if apply {
            "SELECT u.script_pubkey,u.state,u.created_block,u.address,u.covenant_id, \
                    c.script_hash,c.address,c.constructor_args,c.template_name,c.classification_status \
             FROM covenant_utxos u JOIN covenants c ON c.covenant_id=u.covenant_id \
             WHERE u.txid=$1 AND u.vout=$2 FOR UPDATE OF u"
        } else {
            "SELECT u.script_pubkey,u.state,u.created_block,u.address,u.covenant_id, \
                    c.script_hash,c.address,c.constructor_args,c.template_name,c.classification_status \
             FROM covenant_utxos u JOIN covenants c ON c.covenant_id=u.covenant_id \
             WHERE u.txid=$1 AND u.vout=$2"
        };
        let (
            script,
            previous_state,
            created_block,
            output_address,
            covenant_id,
            classified_hash,
            covenant_address,
            state,
            template_name,
            classification_status,
        ): (
            Vec<u8>,
            Option<Value>,
            Vec<u8>,
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            Option<Value>,
            Option<String>,
            String,
        ) = sqlx::query_as(lookup)
            .bind(&txid)
            .bind(vout)
            .fetch_one(&mut *conn)
            .await
            .context("indexed wrapper controller output is absent")?;
        anyhow::ensure!(
            &covenant_id == action_covenant_id && &created_block == action_block,
            "indexed wrapper continuation disagrees with its accepted action"
        );
        let continuation_recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM covenant_actions WHERE txid=$1 \
             AND covenant_id=$2 AND block_hash=$3 AND action='continuation' \
             AND outputs->>'vout'=$4)",
        )
        .bind(&txid)
        .bind(&covenant_id)
        .bind(&created_block)
        .bind(vout.to_string())
        .fetch_one(&mut *conn)
        .await?;
        anyhow::ensure!(
            continuation_recorded,
            "indexed wrapper continuation action is missing"
        );
        anyhow::ensure!(
            template_name.as_deref() == Some("KCC20Wrapper") && classification_status == "matched",
            "indexed wrapper reveal classification is unverified"
        );
        anyhow::ensure!(
            p2sh_script_hash(&script)
                .is_some_and(|hash| hash.as_slice() == classified_hash.as_slice())
                && output_address == covenant_address,
            "indexed wrapper controller output disagrees with classified script or address"
        );
        let script_hash: [u8; 32] = classified_hash
            .as_slice()
            .try_into()
            .context("indexed wrapper script hash is invalid")?;
        ensure_wrapper_output_address(&output_address, &script_hash)?;
        let state = state.context("indexed wrapper constructor state is missing")?;
        let state_fields = state
            .as_object()
            .context("indexed wrapper constructor state is invalid")?;
        anyhow::ensure!(
            !state_fields.is_empty()
                && state_fields
                    .iter()
                    .all(|(key, value)| decoded_args.get(key) == Some(value)),
            "indexed wrapper action disagrees with classified constructor"
        );
        let changed = previous_state.as_ref() != Some(&state);
        if apply && changed {
            let updated = sqlx::query(
                "UPDATE covenant_utxos SET state=$1 WHERE txid=$2 AND vout=$3 \
                 AND script_pubkey=$4 AND state IS NOT DISTINCT FROM $5",
            )
            .bind(&state)
            .bind(&txid)
            .bind(vout)
            .bind(&script)
            .bind(&previous_state)
            .execute(&mut *conn)
            .await?
            .rows_affected();
            anyhow::ensure!(updated == 1, "wrapper controller changed during repair");
            repo::mark_kcc20_projection_dirty_tx(
                &mut conn,
                "wrapper_action_state_repair",
                Some(&txid),
            )
            .await?;
        }
        conn.commit().await?;
        Ok(WrapperActionStateRepairReport {
            txid: transaction_id.to_string(),
            controller_vout: vout,
            previous_state,
            verified_state: state,
            changed,
            applied: apply,
        })
    }

    /// Repair one accepted genesis transaction using the same verified mapping
    /// as live ingest. This never overwrites an existing state or moves a cursor.
    pub async fn repair_claimed_genesis_states(
        &self,
        source: &RestTransaction,
        apply: bool,
    ) -> Result<GenesisStateRepairReport> {
        anyhow::ensure!(source.is_accepted, "source transaction is not accepted");
        let accepting_hash = source.accepting_block_hash.as_deref()
            .context("source transaction has no acceptance evidence")?;
        anyhow::ensure!(
            hex::decode(accepting_hash).is_ok_and(|hash| hash.len() == 32),
            "source transaction has an invalid accepting block hash"
        );
        let claimed = source
            .payload
            .as_deref()
            .and_then(claim::parse_payload_envelope)
            .context("source transaction has no supported deploy claim")?;
        anyhow::ensure!(
            matches!(claimed.tmpl.as_str(), "KCC20" | "KCC20FeeTicket"),
            "source transaction is not a KCC20 or FeeTicket genesis"
        );
        let (covenant_id, states) = claimed_genesis_states(source, &claimed)?
            .context("deploy claim did not match accepted outputs")?;
        let txid = hex::decode(&source.transaction_id)?;
        anyhow::ensure!(txid.len() == 32, "source transaction id must be 32 bytes");
        let stored_claim: Value = sqlx::query_scalar::<_, Option<Value>>(
            "SELECT claimed_args FROM covenants WHERE covenant_id=$1 AND genesis_txid=$2 AND claimed_template=$3",
        )
        .bind(&covenant_id)
        .bind(&txid)
        .bind(&claimed.tmpl)
        .fetch_optional(&self.pool)
        .await?
        .context("accepted genesis covenant or claim is absent from database")?
        .context("accepted genesis has no stored deploy claim")?;
        anyhow::ensure!(
            stored_claim == claim::claimed_args_jsonb(&claimed),
            "stored deploy claim disagrees with source transaction"
        );

        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        if apply {
            self.acquire_persist_writer_lock(&mut conn).await?;
        }
        let mut null_states_found = 0;
        let mut states_repaired = 0;
        for (vout, state) in &states {
            let output = source.outputs.iter().find(|output| output.index == *vout as u64)
                .context("verified output vanished from source transaction")?;
            let source_script = hex::decode(&output.script_public_key)?;
            let stored: (Vec<u8>, Option<Value>) = sqlx::query_as(
                "SELECT script_pubkey,state FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3 FOR UPDATE",
            )
            .bind(&txid)
            .bind(vout)
            .bind(&covenant_id)
            .fetch_one(&mut *conn)
            .await
            .context("verified genesis output missing from database")?;
            anyhow::ensure!(
                stored.0 == source_script,
                "stored genesis output script disagrees with accepted source"
            );
            if stored.1.is_none() {
                null_states_found += 1;
                if apply {
                    let changed = sqlx::query(
                        "UPDATE covenant_utxos SET state=$1 WHERE txid=$2 AND vout=$3 AND covenant_id=$4 AND state IS NULL AND script_pubkey=$5",
                    )
                    .bind(state)
                    .bind(&txid)
                    .bind(vout)
                    .bind(&covenant_id)
                    .bind(&source_script)
                    .execute(&mut *conn)
                    .await?
                    .rows_affected();
                    anyhow::ensure!(changed == 1, "genesis output changed during repair");
                    states_repaired += changed;
                }
            }
        }
        if states_repaired > 0 {
            repo::mark_kcc20_projection_dirty_tx(
                &mut conn,
                "claimed_genesis_state_repair",
                Some(&txid),
            )
            .await?;
        }
        conn.commit().await?;
        Ok(GenesisStateRepairReport {
            txid: source.transaction_id.clone(),
            covenant_id: hex::encode(covenant_id),
            outputs_verified: states.len(),
            null_states_found,
            states_repaired,
            applied: apply,
        })
    }
    pub fn new(pool: PgPool) -> Self {
        Self::with_network_id(pool, "testnet-10")
    }
    /// Build the REST tip follower's persister with bounded waiting behind
    /// concurrent live writers, so a lock collision does not discard a scan
    /// window and force the follower to repeat its REST hydration work.
    pub fn for_tip_follow(pool: PgPool) -> Result<Self> {
        Self::for_tip_follow_settings(pool, |name| std::env::var(name).ok())
    }
    fn for_tip_follow_settings(
        pool: PgPool,
        setting: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let bulk_enabled = setting("TN12_GENERIC_BULK_PERSIST").as_deref() == Some("1");
        let budget_requested = setting("TN12_GENERIC_WRITER_BUDGET").as_deref() == Some("1");
        let budget_enabled = bulk_enabled && budget_requested;
        let budget_max_txs = if budget_enabled {
            budgeted_batch_size(&setting)?
        } else {
            16
        };
        // A zero value explicitly disables the application deadline for an
        // opted-in repair worker. Other writers retain the short default.
        let acceptance_hold_budget_ms = setting("TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS")
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| if value == 0 { 0 } else { value.clamp(350, 5_000) });
        tracing::info!(
            bulk_enabled,
            budget_requested,
            budget_enabled,
            budget_max_txs = ?budget_enabled.then_some(budget_max_txs),
            acceptance_hold_budget_ms = acceptance_hold_budget_ms.unwrap_or(350),
            "historical generic writer configuration"
        );
        let mut writer = Self::new(pool)
            .with_bounded_writer_lock_wait()
            .with_generic_bulk_persist(bulk_enabled)
            .with_generic_writer_budget(budget_enabled);
        writer.writer_priority = live_pressure::configured(
            setting("TN12_WRITER_LIVE_PRIORITY"),
            live_pressure::WriterPriority::History,
        )?;
        match setting("TN12_HISTORY_READ_PREFETCH").as_deref() {
            None | Some("0") => {}
            Some("1") => {
                writer.read_prefetch = Some(std::sync::Arc::new(tokio::sync::Semaphore::new(2)));
            }
            _ => anyhow::bail!("TN12_HISTORY_READ_PREFETCH must be 0 or 1"),
        }
        tracing::info!(
            enabled = writer.read_prefetch.is_some(),
            max_readers = 2,
            "historical identity read prefetch configuration"
        );
        if let Some(ms) = acceptance_hold_budget_ms {
            writer.historical_acceptance_hold_budget = Duration::from_millis(ms);
        }
        Ok(if budget_enabled {
            // Do not inherit the normal generic batch setting. Only the
            // separate bounded-writer setting can raise this cap.
            writer.with_generic_bulk_max_txs(budget_max_txs)
        } else {
            writer
        })
    }
    /// The live watcher can opt into the existing budgeted generic writer.
    /// Share the validated batch policy with the guarded historical path.
    pub fn for_wrpc(pool: PgPool, network_id: impl Into<String>) -> Result<Self> {
        Self::for_wrpc_settings(pool, network_id, |name| std::env::var(name).ok())
    }
    fn for_wrpc_settings(
        pool: PgPool,
        network_id: impl Into<String>,
        setting: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let enabled = setting("TN12_WRPC_GENERIC_BULK_PERSIST").as_deref() == Some("1");
        let bulk_max_txs = if enabled {
            budgeted_batch_size(&setting)?
        } else {
            16
        };
        let native_genesis = match setting("TN12_WRPC_NATIVE_GENESIS_BULK").as_deref() {
            None | Some("0") => false,
            Some("1") if enabled => true,
            Some("1") => anyhow::bail!("native genesis batching requires live generic bulk persistence"),
            _ => anyhow::bail!("TN12_WRPC_NATIVE_GENESIS_BULK must be 0 or 1"),
        };
        tracing::info!(enabled, native_genesis, bulk_max_txs, "live generic writer configuration");
        let mut writer = Self::with_network_id(pool, network_id)
            .with_bounded_writer_lock_wait()
            .with_generic_bulk_persist(enabled)
            .with_generic_writer_budget(enabled)
            .with_native_genesis_bulk(native_genesis)
            .with_generic_bulk_max_txs(bulk_max_txs);
        writer.writer_priority = live_pressure::configured(
            setting("TN12_WRITER_LIVE_PRIORITY"),
            live_pressure::WriterPriority::Live,
        )?;
        Ok(writer)
    }
    pub fn with_network_id(pool: PgPool, network_id: impl Into<String>) -> Self {
        Self {
            pool,
            decoders: default_registry(),
            network_id: network_id.into(),
            wait_for_writer_lock: false,
            generic_bulk_persist: false,
            native_genesis_bulk: false,
            generic_bulk_max_txs: None,
            generic_writer_budget: false,
            historical_acceptance_hold_budget: Duration::from_millis(350),
            consumer_fence: None,
            settled_recheck_fence: None,
            recovery_session: None,
            read_prefetch: None,
            writer_priority: live_pressure::WriterPriority::Disabled,
            rest_removal_guard: None,
        }
    }
    pub fn with_decoders(pool: PgPool, decoders: DecoderRegistry) -> Self {
        Self {
            pool,
            decoders,
            network_id: "testnet-10".to_string(),
            wait_for_writer_lock: false,
            generic_bulk_persist: false,
            native_genesis_bulk: false,
            generic_bulk_max_txs: None,
            generic_writer_budget: false,
            historical_acceptance_hold_budget: Duration::from_millis(350),
            consumer_fence: None,
            settled_recheck_fence: None,
            recovery_session: None,
            read_prefetch: None,
            writer_priority: live_pressure::WriterPriority::Disabled,
            rest_removal_guard: None,
        }
    }
    pub fn with_bounded_writer_lock_wait(mut self) -> Self {
        self.wait_for_writer_lock = true;
        self
    }
    /// Opt-in, unmatched native genesis only. Continuations and recognized
    /// protocols remain on the scalar writer after in-transaction checks.
    pub fn with_native_genesis_bulk(mut self, enabled: bool) -> Self {
        self.native_genesis_bulk = enabled;
        self
    }
    pub fn with_generic_bulk_persist(mut self, enabled: bool) -> Self {
        self.generic_bulk_persist = enabled;
        self
    }
    /// Override the generic batch limit, clamped to the supported range.
    /// This does not enable bulk persistence or change serial eligibility.
    pub fn with_generic_bulk_max_txs(mut self, max_txs: usize) -> Self {
        self.generic_bulk_max_txs = Some(max_txs.clamp(2, generic_bulk::MAX_TXS));
        self
    }
    /// Experimental historical writer guard. Callers must retain the source
    /// window on error and reconcile committed prefixes before retrying.
    /// The TIP constructor opts in only when both generic bulk persistence and
    /// TN12_GENERIC_WRITER_BUDGET are explicitly enabled. Other roles stay off.
    pub fn with_generic_writer_budget(mut self, enabled: bool) -> Self {
        self.generic_writer_budget = enabled;
        self
    }
    /// Use only before opening the live websocket while a durable write intent
    /// is being reconciled. Normal live writes retain their 350 ms limit.
    pub fn with_startup_recovery_acceptance_budget(mut self) -> Self {
        self.historical_acceptance_hold_budget = Duration::from_secs(5);
        self
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// CLI compatibility: bounded pages, with all progress persisted between pages.
    pub async fn normalize_replayed_genesis(&self, start: u64, width: u64) -> Result<(u64, u64)> {
        self.normalize_genesis_window(start, width).await
    }

    pub(crate) async fn apply_genesis_candidate(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        covenant_id: &[u8],
    ) -> Result<(u64, u64)> {
        let missing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM covenant_genesis_progress p JOIN covenants c USING(covenant_id) WHERE p.covenant_id=$1 AND p.baseline_complete AND p.best_txid IS NULL)")
            .bind(covenant_id).fetch_one(&mut **tx).await?;
        if missing {
            return Err(identity::missing_genesis(tx, covenant_id).await?.into());
        }
        let changed: Vec<(Vec<u8>, Vec<u8>, i32)> = sqlx::query_as(
            r#"
            UPDATE covenants c SET genesis_txid=e.best_txid, genesis_vout=e.best_vout,
                genesis_block=e.best_block, created_at_ms=e.best_time
            FROM covenant_genesis_progress e WHERE c.covenant_id=e.covenant_id AND e.covenant_id=$1 AND e.baseline_complete AND e.best_txid IS NOT NULL
              AND (c.genesis_txid,c.genesis_vout,c.genesis_block,c.created_at_ms)
                  IS DISTINCT FROM (e.best_txid,e.best_vout,e.best_block,e.best_time)
            RETURNING c.covenant_id,c.genesis_txid,c.genesis_vout
            "#,
        )
        .bind(covenant_id)
        .fetch_all(&mut **tx)
        .await
        .context("normalize replayed covenant genesis")?;
        let mut actions = 0_u64;
        let mut dirty_txids = Vec::new();
        for (covenant_id, genesis_txid, genesis_vout) in &changed {
            // Genesis coordinates also affect the other read models. Activity
            // only needs the transactions whose action labels change below.
            dirty_txids.push(genesis_txid.clone());
            // Some script identities group independent deploys under one ID.
            // Their action labels cannot be derived from the earliest output.
            // Keep the genesis coordinate current, but leave those labels alone.
            let canonical_deploys: i64 = sqlx::query_scalar(
                r#"SELECT count(*) FROM (
                     SELECT 1 FROM covenant_actions a
                     JOIN blocks b ON b.hash=a.block_hash
                     WHERE a.covenant_id=$1 AND a.action='deploy' AND b.is_chain_block
                     LIMIT 2
                   ) deploys"#,
            )
            .bind(covenant_id)
            .fetch_one(&mut **tx)
            .await
            .context("count canonical deploys before replay relabel")?;
            if canonical_deploys > 1 {
                continue;
            }
            // Replay may have already inserted a continuation for the old
            // deploy's outpoint. Relabeling that deploy would violate the
            // continuation uniqueness index. Remove only an otherwise
            // identical duplicate, keeping the existing continuation.
            let redundant_deploy_txids: Vec<Vec<u8>> = sqlx::query_scalar(
                r#"DELETE FROM covenant_actions deploy
                   USING covenant_actions continuation
                   WHERE deploy.covenant_id=$1 AND deploy.action='deploy'
                     AND deploy.txid<>$2 AND deploy.outputs ? 'vout'
                     AND continuation.covenant_id=deploy.covenant_id
                     AND continuation.txid=deploy.txid
                     AND continuation.action='continuation'
                     AND continuation.outputs->>'vout'=deploy.outputs->>'vout'
                     AND (to_jsonb(deploy)-'id'-'action') =
                         (to_jsonb(continuation)-'id'-'action')
                     AND EXISTS (SELECT 1 FROM blocks b
                       WHERE b.hash=deploy.block_hash AND b.is_chain_block)
                   RETURNING deploy.txid"#,
            )
            .bind(covenant_id)
            .bind(genesis_txid)
            .fetch_all(&mut **tx)
            .await
            .context("remove redundant old canonical deploy after replay")?;
            actions += redundant_deploy_txids.len() as u64;
            dirty_txids.extend(redundant_deploy_txids);
            // Only a changed genesis can invalidate deploy labels. Use the
            // covenant and txid indexes instead of scanning every action.
            let demoted_txids: Vec<Vec<u8>> = sqlx::query_scalar(
                r#"UPDATE covenant_actions a SET action='continuation'
                   WHERE a.covenant_id=$1 AND a.action='deploy' AND a.txid<>$2
                     AND EXISTS (SELECT 1 FROM blocks b WHERE b.hash=a.block_hash AND b.is_chain_block)
                   RETURNING a.txid"#,
            )
            .bind(covenant_id)
            .bind(genesis_txid)
            .fetch_all(&mut **tx)
            .await
            .context("demote old canonical deploy after replay")?;
            actions += demoted_txids.len() as u64;
            dirty_txids.extend(demoted_txids);
            // A transaction may produce several outputs in the same family.
            // Deploy identity is unique per covenant/transaction, while each
            // continuation retains its output identity. Promote the genesis
            // outpoint only; an existing deploy already represents it.
            actions += sqlx::query(
                r#"WITH candidates AS MATERIALIZED (
                     SELECT a.id,a.outputs->>'vout' AS vout
                     FROM covenant_actions a
                     WHERE a.covenant_id=$1 AND a.txid=$2 AND a.action='continuation'
                       AND EXISTS (SELECT 1 FROM blocks b WHERE b.hash=a.block_hash AND b.is_chain_block)
                   ), chosen AS (
                     SELECT id FROM candidates
                     WHERE vout=$3::text
                        OR (vout IS NULL AND (SELECT count(*) FROM candidates)=1)
                     ORDER BY id LIMIT 1
                   )
                   UPDATE covenant_actions a SET action='deploy'
                   FROM chosen WHERE a.id=chosen.id
                     AND NOT EXISTS (SELECT 1 FROM covenant_actions deployed
                       WHERE deployed.covenant_id=$1 AND deployed.txid=$2 AND deployed.action='deploy')"#,
            )
            .bind(covenant_id)
            .bind(genesis_txid)
            .bind(genesis_vout.to_string())
            .execute(&mut **tx)
            .await
            .context("promote restored canonical deploy after replay")?
            .rows_affected();
        }
        let covenants = changed.len() as u64;
        if covenants > 0 {
            // An unscoped marker requests a full feed rebuild, which is
            // intentionally disabled on live workers. Queue the changed txids
            // in this same transaction so incremental projection can advance.
            repo::mark_kcc20_projection_dirty_txids_tx(tx, "settled_replay_genesis", &dirty_txids)
                .await?;
        }
        sqlx::query("UPDATE covenant_genesis_progress SET applied_version=version,blocker=NULL,retry_at_ms=0 WHERE covenant_id=$1")
            .bind(covenant_id).execute(&mut **tx).await?;
        Ok((covenants, actions))
    }

    pub fn decoders(&self) -> &DecoderRegistry {
        &self.decoders
    }

    /// Repository repair entry points must serialize with ingestion and reorgs.
    /// Fail fast on contention so a repair command can be retried deliberately.
    pub(crate) async fn begin_repair_transaction(
        pool: &PgPool,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
        let writer = Self::new(pool.clone());
        let mut transaction = pool.begin().await?;
        Self::set_persist_query_limits(&mut transaction).await?;
        writer.acquire_persist_writer_lock(&mut transaction).await?;
        Ok(transaction)
    }

    async fn set_persist_query_limits(
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<()> {
        let lock_timeout = std::env::var("TN12_PERSIST_LOCK_TIMEOUT")
            .unwrap_or_else(|_| DEFAULT_PERSIST_LOCK_TIMEOUT.to_string());
        let statement_timeout = std::env::var("TN12_PERSIST_STATEMENT_TIMEOUT")
            .unwrap_or_else(|_| DEFAULT_PERSIST_STATEMENT_TIMEOUT.to_string());

        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(lock_timeout)
            .execute(&mut **conn)
            .await
            .context("set persist lock_timeout")?;
        sqlx::query("SELECT set_config('statement_timeout', $1, true)")
            .bind(statement_timeout)
            .execute(&mut **conn)
            .await
            .context("set persist statement_timeout")?;
        Ok(())
    }

    async fn acquire_persist_writer_lock(
        &self,
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<()> {
        self.acquire_recovery_writer_lock(conn, None).await
    }

    async fn acquire_recovery_writer_lock(
        &self,
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        owner: Option<&PagedRecoveryOwner>,
    ) -> Result<()> {
        self.wait_for_live_pressure(conn).await?;
        if self.wait_for_writer_lock {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(PERSIST_WRITER_LOCK_KEY).execute(&mut **conn).await
                .map_err(|error| classify_persist_sqlx_error("acquire persist writer lock", error))?;
        } else {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
                .bind(PERSIST_WRITER_LOCK_KEY).fetch_one(&mut **conn).await
                .map_err(|error| classify_persist_sqlx_error("acquire persist writer lock", error))?;
            if !acquired {
                return Err(TransientPersistError::writer_lock_busy("acquire persist writer lock").into());
            }
        }
        // Partial block removal must not race repair/direct ingestion. The
        // journal and existing health/coverage gates remain active until final
        // source verification and acknowledgement delete the fenced plan.
        let foreign_plan: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_plans WHERE exclusive_writes AND ($1::text IS NULL OR intent_key<>$1))"
        ).bind(owner.map(|owner| owner.intent_key.as_str())).fetch_one(&mut **conn).await?;
        if foreign_plan {
            return Err(TransientPersistError::writer_lock_busy("chunked recovery owns canonical writes").into());
        }
        if let Some(owner) = owner {
            paged_recovery::lock_intent_and_owner(conn, owner).await?;
        }
        self.verify_rest_removal_guard(conn).await?;
        self.verify_consumer_fence(conn).await
    }

    async fn backfill_classification_best_effort(
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        covenant_id: &[u8],
        template_name: &str,
        args: &Value,
        kind: &str,
    ) -> Result<bool> {
        sqlx::query("SAVEPOINT optional_classification_backfill")
            .execute(&mut **conn)
            .await
            .context("start optional classification backfill savepoint")?;

        let update_result = async {
            sqlx::query("SELECT set_config('lock_timeout', $1, true)")
                .bind(OPTIONAL_CLASSIFICATION_LOCK_TIMEOUT)
                .execute(&mut **conn)
                .await
                .context("set optional classification lock_timeout")?;
            sqlx::query("SELECT set_config('statement_timeout', $1, true)")
                .bind(OPTIONAL_CLASSIFICATION_STATEMENT_TIMEOUT)
                .execute(&mut **conn)
                .await
                .context("set optional classification statement_timeout")?;

            let result = sqlx::query(
                r#"WITH target AS (
                       SELECT covenant_id
                       FROM covenants
                       WHERE covenant_id = $4
                         AND (template_name IS NULL OR template_name = $1)
                       FOR UPDATE SKIP LOCKED
                   )
                   UPDATE covenants c
                   SET template_name = $1,
                       constructor_args = $2,
                       classification_kind = $3,
                       classification_status = 'matched'
                   FROM target
                   WHERE c.covenant_id = target.covenant_id
                     AND ROW(
                           c.template_name,
                           c.constructor_args,
                           c.classification_kind,
                           c.classification_status
                         ) IS DISTINCT FROM ROW($1, $2, $3, 'matched')"#,
            )
            .bind(template_name)
            .bind(args)
            .bind(kind)
            .bind(covenant_id)
            .execute(&mut **conn)
            .await
            .context("backfill classification")?;

            Ok::<u64, anyhow::Error>(result.rows_affected())
        }
        .await;

        match update_result {
            Ok(rows_affected) => {
                sqlx::query("RELEASE SAVEPOINT optional_classification_backfill")
                    .execute(&mut **conn)
                    .await
                    .context("release optional classification backfill savepoint")?;
                Self::set_persist_query_limits(conn).await?;
                Ok(rows_affected > 0)
            }
            Err(error) if is_transient_persist_error(&error) => {
                sqlx::query("ROLLBACK TO SAVEPOINT optional_classification_backfill")
                    .execute(&mut **conn)
                    .await
                    .context("rollback optional classification backfill savepoint")?;
                sqlx::query("RELEASE SAVEPOINT optional_classification_backfill")
                    .execute(&mut **conn)
                    .await
                    .context("release rolled back optional classification backfill savepoint")?;
                Self::set_persist_query_limits(conn).await?;
                tracing::warn!(
                    target: "classification_deferred",
                    covenant_id = %hex::encode(covenant_id),
                    template = %template_name,
                    error = %error,
                    "deferred covenant classification backfill; reclassify job can repair it later"
                );
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Re-run the decoder against a single covenant's most-recent spend and
    /// backfill `covenants.template_name` + `covenants.constructor_args` +
    /// `covenant_actions.entrypoint` for the matching rows.
    ///
    /// `covenant_id`     — the 32-byte canonical id, or legacy P2SH script_hash fallback
    /// `action_id`       — exact `covenant_actions.id` selected for this spend input
    /// `spend_txid`      — txid of the spend whose signature_script reveals the redeem script
    /// `signature_script_hex` — full hex of the spend input's signature_script
    ///
    /// Returns `Ok(Some(template_name))` on match, `Ok(None)` if no decoder
    /// matched (covenant remains unclassified). Idempotent: re-running on an
    /// already-classified row is a no-op via the `template_name IS NULL`
    /// guard in the UPDATE.
    pub async fn reclassify_covenant(
        &self,
        action_id: i64,
        covenant_id: &[u8],
        spend_txid: &[u8],
        signature_script_hex: &str,
    ) -> Result<Option<String>> {
        let sig_script =
            hex::decode(signature_script_hex).context("decoding signature_script hex")?;
        let Some(reveal) = extract_last_push(&sig_script) else {
            self.mark_unmatched(covenant_id).await?;
            return Ok(None);
        };
        let Some(mut classification) = classify_reveal(&self.decoders, &sig_script, &reveal) else {
            self.mark_unmatched(covenant_id).await?;
            return Ok(None);
        };
        let action_args = match classification.template_name.as_str() {
            "KCC20" => kcc20_standard::decode_action_args_for_reveal(&sig_script, &reveal),
            "KCC20Orderbook" => kcc20_orderbook::decode_action_args(&sig_script),
            "KCC20Wrapper" => kcc20_wrapper::decode_action_args(&sig_script),
            "KCC20FeeTicket" => kcc20_fee_ticket::decode_action_args(&sig_script),
            "KCC20SnapshotController" => {
                kcc20_snapshot_controller::decode_claim_transition(&sig_script, &reveal)
            }
            "KCC20SnapshotBootstrap" => {
                kcc20_snapshot_bootstrap::decode_bootstrap_action(&sig_script, &reveal)
            }
            _ => Ok(None),
        };
        match action_args {
            Ok(Some(action_args)) => {
                let mut decoded_args = Some(classification.args);
                merge_json_object(&mut decoded_args, action_args);
                classification.args = decoded_args.unwrap_or(Value::Null);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    action_id,
                    template = %classification.template_name,
                    %error,
                    "reclassified action arguments could not be decoded"
                );
            }
        }

        let mut conn = self
            .pool
            .begin()
            .await
            .context("begin reclassify transaction")?;
        Self::set_persist_query_limits(&mut conn).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        if classification.template_name == "KCC20" {
            self.backfill_kcc20_states(
                &mut conn,
                action_id,
                covenant_id,
                spend_txid,
                &reveal,
                &classification.args,
            )
            .await?;
        }
        let covenant_update = sqlx::query(
            r#"UPDATE covenants
               SET template_name = CASE
                       WHEN template_name IS NULL THEN $1
                       ELSE template_name
                   END,
                   constructor_args = CASE
                       WHEN template_name IS NULL OR template_name = $1 THEN $2
                       ELSE constructor_args
                   END,
                   classification_kind = CASE
                       WHEN template_name IS NULL OR template_name = $1 THEN $3
                       ELSE classification_kind
                   END,
                   classification_status = 'matched'
               WHERE covenant_id = $4
                 AND (
                     template_name IS NULL
                     OR template_name = $1
                     OR (
                         template_name IN ('KCC20Orderbook', 'KCC20Wrapper')
                         AND $1 IN ('KCC20Orderbook', 'KCC20Wrapper')
                     )
                 )"#,
        )
        .bind(&classification.template_name)
        .bind(&classification.args)
        .bind(classification.kind)
        .bind(covenant_id)
        .execute(&mut *conn)
        .await
        .context("UPDATE covenants in reclassify")?;
        if covenant_update.rows_affected() != 1 {
            return Err(anyhow::anyhow!(
                "reclassify target covenant was not updated for action {action_id}"
            ));
        }

        let action_update = sqlx::query(
            r#"UPDATE covenant_actions
               SET entrypoint = COALESCE($1, entrypoint),
                   decoded_args = $4
               WHERE id = $5 AND covenant_id = $2 AND txid = $3
                 AND action = 'spend'
                 AND ($1::TEXT IS NULL OR entrypoint IS NULL OR entrypoint = $1)"#,
        )
        .bind(classification.entrypoint.as_deref())
        .bind(covenant_id)
        .bind(spend_txid)
        .bind(&classification.args)
        .bind(action_id)
        .execute(&mut *conn)
        .await
        .context("UPDATE covenant_actions in reclassify")?;
        if action_update.rows_affected() != 1 {
            return Err(anyhow::anyhow!(
                "reclassify target action {action_id} was not updated"
            ));
        }

        if is_kcc20_template(&classification.template_name) {
            repo::mark_kcc20_projection_dirty_tx(
                &mut conn,
                "kcc20_reclassification",
                Some(spend_txid),
            )
            .await
            .context("mark KCC20 projections dirty after reclassify")?;
            tracing::debug!(
                target: "kcc20_read_models",
                covenant_id = %hex::encode(covenant_id),
                template = %classification.template_name,
                "KCC20 classification changed; projector will refresh read models"
            );
        }

        conn.commit()
            .await
            .context("commit reclassify transaction")?;

        Ok(Some(classification.template_name))
    }

    // Run under the same writer lock as acceptance/reorg persistence. A removed
    // action cannot restore balances, and every state must open the stored P2SH.
    async fn backfill_kcc20_states(
        &self,
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action_id: i64,
        covenant_id: &[u8],
        spend_txid: &[u8],
        reveal: &[u8],
        args: &Value,
    ) -> Result<()> {
        let input: Value = sqlx::query_scalar(
            "SELECT inputs FROM covenant_actions WHERE id = $1 AND covenant_id = $2 AND txid = $3 AND action = 'spend' FOR UPDATE",
        ).bind(action_id).bind(covenant_id).bind(spend_txid).fetch_one(&mut **conn).await
            .context("load accepted action for KCC20 state reconstruction")?;
        let prev_txid = hex::decode(
            input
                .pointer("/previousOutpoint/hash")
                .and_then(Value::as_str)
                .context("reclassification input has no outpoint hash")?,
        )?;
        let prev_vout = json_i32(input.pointer("/previousOutpoint/index"))
            .context("reclassification input has no output index")?;
        let input_state = serde_json::to_value(kcc20_standard::decode_reveal_state(reveal)?)?;
        let mut updates = vec![(prev_txid, prev_vout, input_state)];
        if let Some(states) = args.get("nextStates").and_then(Value::as_array) {
            let indices: Vec<i32> = sqlx::query_scalar(
                "SELECT vout FROM covenant_utxos WHERE txid = $1 AND covenant_id = $2 ORDER BY vout",
            ).bind(spend_txid).bind(covenant_id).fetch_all(&mut **conn).await?;
            anyhow::ensure!(
                indices.len() == states.len(),
                "KCC20 reclassification output count mismatch"
            );
            updates.extend(
                indices
                    .into_iter()
                    .zip(states)
                    .map(|(index, state)| (spend_txid.to_vec(), index, state.clone())),
            );
        }
        if let Some(outputs) = args.get("outputStates").and_then(Value::as_array) {
            for output in outputs {
                let index = json_i32(output.get("outputIndex"))
                    .context("missing reconstructed output index")?;
                let state = output
                    .get("state")
                    .context("missing reconstructed output state")?;
                updates.push((spend_txid.to_vec(), index, state.clone()));
            }
        }
        for (txid, vout, state) in updates {
            let expected_script =
                kcc20_standard::script_for_state_value_with_reveal(&state, reveal)?;
            let expected_hash = blake2b_256(&expected_script);
            let stored: (Vec<u8>, Option<Value>) = sqlx::query_as(
                "SELECT script_pubkey, state FROM covenant_utxos WHERE txid = $1 AND vout = $2 AND covenant_id = $3 FOR UPDATE",
            ).bind(&txid).bind(vout).bind(covenant_id).fetch_one(&mut **conn).await
                .context("missing historical KCC20 output; replay acceptance history first")?;
            anyhow::ensure!(
                p2sh_script_hash(&stored.0) == Some(expected_hash),
                "KCC20 reconstructed state does not match accepted output script"
            );
            if let Some(existing) = stored.1 {
                // Compare script commitments, allowing older JSON without descriptive fields.
                anyhow::ensure!(
                    kcc20_standard::script_for_state_value_with_reveal(&existing, reveal)?
                        == expected_script,
                    "KCC20 historical state conflicts with reconstructed state"
                );
            } else {
                sqlx::query("UPDATE covenant_utxos SET state = $1 WHERE txid = $2 AND vout = $3 AND covenant_id = $4")
                    .bind(state).bind(txid).bind(vout).bind(covenant_id).execute(&mut **conn).await?;
            }
        }
        Ok(())
    }

    async fn mark_unmatched(&self, covenant_id: &[u8]) -> Result<()> {
        let mut conn = self.pool.begin().await?;
        if self.consumer_fence.is_some() || self.recovery_session.is_some() {
            Self::set_persist_query_limits(&mut conn).await?;
            self.acquire_persist_writer_lock(&mut conn).await?;
        }
        sqlx::query(
            r#"UPDATE covenants
               SET classification_kind = 'unknown',
                   classification_status = 'unmatched'
               WHERE covenant_id = $1
                 AND classification_status <> 'matched'
                 AND (
                     classification_kind IS DISTINCT FROM 'unknown'
                     OR classification_status IS DISTINCT FROM 'unmatched'
                 )"#,
        )
        .bind(covenant_id)
        .execute(&mut *conn)
        .await
        .context("mark covenant unmatched")?;
        conn.commit().await?;
        Ok(())
    }

    async fn store_deploy_payload_claim_best_effort(
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tmpl: &str,
        blob: &Value,
        covenant_id: &[u8],
    ) -> Result<u64> {
        sqlx::query("SAVEPOINT optional_deploy_claim")
            .execute(&mut **conn)
            .await
            .context("start optional deploy claim savepoint")?;

        let update_result = async {
            sqlx::query("SELECT set_config('lock_timeout', $1, true)")
                .bind(OPTIONAL_DEPLOY_CLAIM_LOCK_TIMEOUT)
                .execute(&mut **conn)
                .await
                .context("set optional deploy claim lock_timeout")?;
            sqlx::query("SELECT set_config('statement_timeout', $1, true)")
                .bind(OPTIONAL_DEPLOY_CLAIM_STATEMENT_TIMEOUT)
                .execute(&mut **conn)
                .await
                .context("set optional deploy claim statement_timeout")?;

            let result = sqlx::query(
                r#"WITH claim_target AS (
                       SELECT covenant_id
                       FROM covenants
                       WHERE covenant_id = $3
                         AND claimed_template IS NULL
                       FOR UPDATE SKIP LOCKED
                   )
                   UPDATE covenants c
                   SET claimed_template = $1,
                       claimed_args = $2,
                       claim_source = COALESCE(c.claim_source, 'payload')
                   FROM claim_target
                   WHERE c.covenant_id = claim_target.covenant_id"#,
            )
            .bind(tmpl)
            .bind(blob)
            .bind(covenant_id)
            .execute(&mut **conn)
            .await
            .context("store claimed_template + claimed_args at deploy")?;

            Self::set_persist_query_limits(conn).await?;
            Ok::<u64, anyhow::Error>(result.rows_affected())
        }
        .await;

        match update_result {
            Ok(rows_affected) => {
                sqlx::query("RELEASE SAVEPOINT optional_deploy_claim")
                    .execute(&mut **conn)
                    .await
                    .context("release optional deploy claim savepoint")?;
                tracing::debug!(
                    covenant_id = %hex::encode(covenant_id),
                    rows_affected,
                    "stored optional deploy payload claim"
                );
                Ok(rows_affected)
            }
            Err(error) => {
                sqlx::query("ROLLBACK TO SAVEPOINT optional_deploy_claim")
                    .execute(&mut **conn)
                    .await
                    .context("rollback optional deploy claim savepoint")?;
                sqlx::query("RELEASE SAVEPOINT optional_deploy_claim")
                    .execute(&mut **conn)
                    .await
                    .context("release optional deploy claim savepoint after rollback")?;
                tracing::warn!(
                    covenant_id = %hex::encode(covenant_id),
                    error = %error,
                    "skipped optional deploy payload claim after bounded timeout"
                );
                Ok(0)
            }
        }
    }

    async fn retry_deploy_payload_claim_after_commit(
        &self,
        covenant_id: &[u8],
        claim: &claim::ClaimedDeployment,
    ) {
        let result = tokio::time::timeout(
            OPTIONAL_DEPLOY_CLAIM_RETRY_TIMEOUT,
            self.store_deploy_payload_claim_after_commit_bounded(covenant_id, claim),
        )
        .await;

        match result {
            Ok(Ok(rows_affected)) => {
                tracing::debug!(
                    covenant_id = %hex::encode(covenant_id),
                    rows_affected,
                    "retried deploy payload claim after commit"
                );
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    covenant_id = %hex::encode(covenant_id),
                    error = %error,
                    "deploy payload claim retry failed after commit"
                );
            }
            Err(_) => {
                tracing::warn!(
                    covenant_id = %hex::encode(covenant_id),
                    "deploy payload claim retry timed out after commit"
                );
            }
        }
    }

    async fn store_deploy_payload_claim_after_commit_bounded(
        &self,
        covenant_id: &[u8],
        claim: &claim::ClaimedDeployment,
    ) -> Result<u64> {
        let mut conn = self
            .pool
            .begin()
            .await
            .context("begin deploy claim retry tx")?;
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(OPTIONAL_DEPLOY_CLAIM_LOCK_TIMEOUT)
            .execute(&mut *conn)
            .await
            .context("set deploy claim retry lock_timeout")?;
        sqlx::query("SELECT set_config('statement_timeout', $1, true)")
            .bind(OPTIONAL_DEPLOY_CLAIM_STATEMENT_TIMEOUT)
            .execute(&mut *conn)
            .await
            .context("set deploy claim retry statement_timeout")?;
        if self.consumer_fence.is_some() || self.recovery_session.is_some() {
            self.acquire_persist_writer_lock(&mut conn).await?;
        }

        let rows_affected =
            repo::store_payload_claim_for_covenant_tx(&mut conn, covenant_id, claim)
                .await
                .context("store deploy payload claim after commit")?;
        conn.commit()
            .await
            .context("commit deploy claim retry tx")?;

        Ok(rows_affected)
    }
}

impl PgPersister {
    /// Own the writer lock before checking whether any removed block exists.
    /// A single transaction keeps the whole removal event atomic.
    async fn revert_blocks_locked(&self, block_hashes: &[Vec<u8>]) -> Result<Vec<RevertStats>> {
        self.revert_blocks_locked_checked(block_hashes, None).await
    }

    async fn revert_blocks_locked_checked(
        &self,
        block_hashes: &[Vec<u8>],
        impacts: Option<&[RecoveryBlockImpact]>,
    ) -> Result<Vec<RevertStats>> {
        if block_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.pool.begin().await.context("begin block removals")?;
        Self::set_persist_query_limits(&mut conn).await?;
        // Short ordered reorg writes must not pay per-statement JIT compilation.
        sqlx::query("SET LOCAL jit=off").execute(&mut *conn).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        if let Some(impacts) = impacts {
            recovery_impact::validate_locked(&mut conn, impacts).await?;
        }
        Self::record_rest_removals(&mut conn, block_hashes).await?;
        let known_blocks: Vec<(Vec<u8>, bool)> =
            sqlx::query_as("SELECT hash,is_chain_block FROM blocks WHERE hash = ANY($1::bytea[]) ORDER BY hash FOR UPDATE")
                .bind(block_hashes)
                .fetch_all(&mut *conn)
                .await
                .context("lookup indexed blocks under reorg writer lock")?;
        let removed_canonical: Vec<Vec<u8>> = known_blocks
            .iter()
            .filter(|(_, canonical)| *canonical)
            .map(|(hash, _)| hash.clone())
            .collect();
        let known_hashes: HashSet<Vec<u8>> =
            known_blocks.into_iter().map(|(hash, _)| hash).collect();
        if !known_hashes.is_empty() {
            sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair', 'on', TRUE)")
                .execute(&mut *conn)
                .await
                .context("defer covenant summary repair during block removals")?;
        }
        Self::invalidate_historical_acceptance_targets(&mut conn, &removed_canonical).await?;
        let mut results = Vec::with_capacity(block_hashes.len());
        for block_hash in block_hashes {
            if known_hashes.contains(block_hash) {
                results.push(self.revert_block_tx(&mut conn, block_hash).await?);
            } else {
                results.push(RevertStats::default());
            }
        }
        Self::retire_removed_acceptance_replacements(&mut conn, &removed_canonical).await?;
        conn.commit().await.context("commit block removals")?;
        Ok(results)
    }

    async fn revert_block_tx(
        &self,
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        block_hash: &[u8],
    ) -> Result<RevertStats> {
        self.revert_block_effects_tx(conn, block_hash, None, true).await
    }

    async fn revert_block_effects_tx(
        &self,
        conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        block_hash: &[u8],
        transaction_ids: Option<&[Vec<u8>]>,
        finalize: bool,
    ) -> Result<RevertStats> {
        let mut stats = RevertStats::default();

        sqlx::query("UPDATE indexer_deferred_decodes SET status='reverted',decoded_at_ms=NULL WHERE block_hash=$1 AND ($2::bytea[] IS NULL OR txid=ANY($2))")
            .bind(block_hash).bind(transaction_ids).execute(&mut **conn).await.context("revoke deferred acceptance on reorg")?;

        let blue_score: Option<i64> =
            sqlx::query_scalar("SELECT blue_score FROM blocks WHERE hash = $1")
                .bind(block_hash)
                .fetch_optional(&mut **conn)
                .await
                .context("lookup block before revert")?;
        let Some(blue_score) = blue_score else {
            return Ok(stats);
        };
        stats.reverted_blue_score = Some(blue_score.max(0) as u64);


        let mut affected_projection_txids: Vec<Vec<u8>> = sqlx::query_scalar(
            r#"
            SELECT txid FROM covenant_actions WHERE block_hash = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2))
            UNION
            SELECT spent_by_txid FROM covenant_utxos
            WHERE spent_block = $1 AND ($2::bytea[] IS NULL OR spent_by_txid=ANY($2)) AND spent_by_txid IS NOT NULL
            UNION
            SELECT txid FROM covenant_utxos WHERE created_block = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2))
            UNION
            SELECT genesis_txid FROM covenants WHERE genesis_block = $1 AND ($2::bytea[] IS NULL OR genesis_txid=ANY($2))
            "#,
        )
        .bind(block_hash).bind(transaction_ids)
        .fetch_all(&mut **conn)
        .await
        .context("collect projection transactions affected by reverted block")?;

        let affected_covenants: Vec<Vec<u8>> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT covenant_id FROM covenant_actions
            WHERE block_hash = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2)) AND action = 'spend'
            UNION
            SELECT DISTINCT covenant_id FROM covenant_utxos
            WHERE spent_block = $1 AND ($2::bytea[] IS NULL OR spent_by_txid=ANY($2))
            "#,
        )
        .bind(block_hash).bind(transaction_ids)
        .fetch_all(&mut **conn)
        .await
        .context("collect covenants affected by reverted spends")?;

        // AFTER-row triggers run after the whole statement has removed its
        // rows. Recounting after an early row would include every removal,
        // then later row triggers would subtract those removals again.
        // Include created outputs even when this block has no indexed spends.
        let affected_summaries: Vec<Vec<u8>> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT covenant_id FROM covenant_utxos
            WHERE covenant_id IS NOT NULL
              AND ((created_block = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2))) OR (spent_block = $1 AND ($2::bytea[] IS NULL OR spent_by_txid=ANY($2))))
            "#,
        )
        .bind(block_hash).bind(transaction_ids)
        .fetch_all(&mut **conn)
        .await
        .context("collect covenant summaries affected by block revert")?;

        // Capture only actual active-set changes before mutation. A row created
        // and spent in the removed block contributes zero; a spent output
        // created elsewhere is reactivated. All observations share the writer
        // lock and transaction with the mutations and final summary update.
        let summary_changes: serde_json::Value = sqlx::query_scalar(
            r#"SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'cid',encode(covenant_id,'hex'),'count_delta',delta,
                'amount_delta',delta*amount_sompi,'txid',encode(txid,'hex'),
                'vout',vout,'address',address,'block',encode(created_block,'hex')
            )), '[]'::jsonb) FROM (
                SELECT u.*, CASE
                    WHEN created_block=$1 AND status='active' THEN -1
                    WHEN spent_block=$1 AND status='spent' AND (created_block<>$1 OR ($2::bytea[] IS NOT NULL AND NOT txid=ANY($2))) THEN 1
                    ELSE 0 END AS delta
                FROM covenant_utxos u
                WHERE covenant_id IS NOT NULL AND ((created_block=$1 AND ($2::bytea[] IS NULL OR txid=ANY($2))) OR (spent_block=$1 AND ($2::bytea[] IS NULL OR spent_by_txid=ANY($2))))
            ) changed"#,
        )
        .bind(block_hash).bind(transaction_ids)
        .fetch_one(&mut **conn)
        .await
            .context("capture active output deltas before block removal")?;
        let summary_fallback: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT a.covenant_id FROM unnest($1::bytea[]) a(covenant_id) \
             LEFT JOIN covenant_summaries s USING(covenant_id) \
             LEFT JOIN covenant_utxos u ON u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout \
             LEFT JOIN blocks b ON b.hash=u.created_block \
             WHERE s.covenant_id IS NULL OR s.active_utxos<0 OR s.total_amount_sompi<0 \
                OR (s.active_utxos>0 AND (u.txid IS NULL OR u.status<>'active' OR \
                    ROW(u.covenant_id,u.address,u.created_block,b.blue_score) IS DISTINCT FROM \
                    ROW(s.covenant_id,s.current_address,s.latest_active_block,s.latest_active_blue_score))) \
                OR (s.active_utxos=0 AND (s.latest_active_txid IS NOT NULL OR s.total_amount_sompi<>0))",
        )
        .bind(&affected_summaries)
        .fetch_all(&mut **conn)
        .await
            .context("identify missing reorg summary baselines")?;

        // Reorgs change many outputs in one statement. Skip incremental
        // summary triggers only for these mutations, then apply their deltas
        // before address normalization or commit.
        sqlx::query("SELECT set_config('tn12.defer_reorg_utxo_summaries', 'on', TRUE)")
            .execute(&mut **conn)
            .await
            .context("defer UTXO summaries during block revert")?;

        let r = sqlx::query(
            r#"UPDATE covenant_utxos
               SET status = 'active',
                   spent_block = NULL,
                   spent_by_txid = NULL
               WHERE spent_block = $1 AND ($2::bytea[] IS NULL OR spent_by_txid=ANY($2))"#,
        )
        .bind(block_hash).bind(transaction_ids)
        .execute(&mut **conn)
        .await
        .context("reactivate utxos spent by reverted block")?;
        stats.utxos_reactivated = r.rows_affected();

        let r = sqlx::query("DELETE FROM covenant_actions WHERE block_hash = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2))")
            .bind(block_hash).bind(transaction_ids)
            .execute(&mut **conn)
            .await
            .context("delete actions from reverted block")?;
        stats.actions_removed = r.rows_affected();

        let r = sqlx::query("DELETE FROM covenant_utxos WHERE created_block = $1 AND ($2::bytea[] IS NULL OR txid=ANY($2))")
            .bind(block_hash).bind(transaction_ids)
            .execute(&mut **conn)
            .await
            .context("delete utxos created by reverted block")?;
        stats.utxos_created_removed = r.rows_affected();

        sqlx::query("SELECT set_config('tn12.defer_reorg_utxo_summaries', 'off', TRUE)")
            .execute(&mut **conn)
            .await
            .context("restore UTXO summary triggers after block revert")?;

        let r = sqlx::query("DELETE FROM covenants WHERE genesis_block = $1 AND ($2::bytea[] IS NULL OR genesis_txid=ANY($2))")
            .bind(block_hash).bind(transaction_ids)
            .execute(&mut **conn)
            .await
            .context("delete covenants created by reverted block")?;
        stats.covenants_removed = r.rows_affected();

        let mut unclassified_covenants = Vec::new();
        for covenant_ids in affected_covenants.chunks(256) {
            // Requeue historical projections only when classification changes.
            // An unrevealed covenant can have millions of unrelated actions.
            let changed: Vec<Vec<u8>> = sqlx::query_scalar(
                r#"UPDATE covenants c
                   SET template_name = NULL,
                       constructor_args = NULL,
                       classification_kind = 'unknown',
                       classification_status = 'unrevealed',
                       claim_verified = FALSE,
                       claim_verified_at_ms = NULL
                   WHERE c.covenant_id = ANY($1::bytea[])
                     AND (
                         c.template_name IS NOT NULL
                         OR c.constructor_args IS NOT NULL
                         OR c.classification_kind IS DISTINCT FROM 'unknown'
                         OR c.classification_status IS DISTINCT FROM 'unrevealed'
                         OR c.claim_verified IS DISTINCT FROM FALSE
                         OR c.claim_verified_at_ms IS NOT NULL
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM covenant_actions a
                         WHERE a.covenant_id = c.covenant_id
                           AND a.action = 'spend'
                     )
                   RETURNING c.covenant_id"#,
            )
            .bind(covenant_ids)
            .fetch_all(&mut **conn)
            .await
            .context("clear classifications only revealed by reverted spends")?;
            stats.covenants_unclassified += changed.len() as u64;
            unclassified_covenants.extend(changed);
        }

        if !unclassified_covenants.is_empty() {
            let historical_txids: Vec<Vec<u8>> = sqlx::query_scalar(
                r#"
                SELECT DISTINCT txid
                FROM covenant_actions
                WHERE covenant_id = ANY($1::BYTEA[])
                "#,
            )
            .bind(&unclassified_covenants)
            .fetch_all(&mut **conn)
            .await
            .context("collect historical projection transactions for unclassified covenants")?;
            affected_projection_txids.extend(historical_txids);
        }

        if !affected_summaries.is_empty() {
            let updated = sqlx::query(include_str!("persist/finalize_reorg_summary_deltas.sql"))
                .bind(&summary_changes)
                .bind(&summary_fallback)
                .execute(&mut **conn)
                .await
                .context("apply block removal summary deltas")?
                .rows_affected();
            let expected: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM covenants WHERE covenant_id=ANY($1::bytea[]) AND NOT covenant_id=ANY($2::bytea[])",
            )
            .bind(&affected_summaries)
            .bind(&summary_fallback)
            .fetch_one(&mut **conn)
            .await?;
            anyhow::ensure!(
                updated == expected as u64,
                "block removal summary delta invariant failed"
            );
        }
        // Rebuild only absent/invalid baselines, never every healthy family.
        for covenant_ids in summary_fallback.chunks(256) {
            sqlx::query(include_str!("persist/finalize_reorg_summaries.sql"))
                .bind(covenant_ids)
                .execute(&mut **conn)
                .await
                .context("rebuild missing covenant summaries after block revert")?;
        }

        // Action addresses are resolved from the current covenant summary at
        // read time, as on the persist path. Rewriting every historical action
        // here holds the live writer lock across an unbounded family history.

        if finalize {
        let r = sqlx::query("DELETE FROM blocks WHERE hash = $1")
            .bind(block_hash)
            .execute(&mut **conn)
            .await
            .context("delete reverted block")?;
        stats.blocks_removed = r.rows_affected();
        }

        if stats.utxos_reactivated > 0
            || stats.actions_removed > 0
            || stats.utxos_created_removed > 0
            || stats.covenants_removed > 0
            || stats.covenants_unclassified > 0
        {
            if !affected_projection_txids.is_empty() {
                repo::mark_kcc20_projection_dirty_txids_tx(
                    conn,
                    "block_revert",
                    &affected_projection_txids,
                )
                .await
                .context("mark KCC20 projection transactions dirty after revert")?;
            }
        }

        Ok(stats)
    }
}

#[async_trait]
impl Persister for PgPersister {
    fn paged_recovery_writer(&self) -> Option<&PgPersister> {
        Some(self)
    }
    async fn prefetch_identities(&self, txids: &[String]) -> Result<bool> {
        self.prefetch_identity_pages(txids).await
    }
    async fn historical_acceptance_cohort(
        &self,
        old_hashes: &[Vec<u8>],
    ) -> Result<HistoricalAcceptanceCohort> {
        PgPersister::historical_acceptance_cohort(self, old_hashes).await
    }
    async fn reconcile_historical_acceptance_map(
        &self,
        proof: &HistoricalAcceptanceMapProof,
    ) -> Result<AcceptanceReconciliationStats> {
        PgPersister::reconcile_historical_acceptance_map(self, proof).await
    }
    async fn classify_historical_acceptance_outcome(
        &self,
        proof: &HistoricalAcceptanceMapProof,
    ) -> Result<HistoricalAcceptanceOutcome> {
        PgPersister::classify_historical_acceptance_outcome(self, proof).await
    }

    async fn persist_batch(&self, txs: &[RestTransaction]) -> Result<PersistStats> {
        self.require_rest_guard_transactions(txs)?;
        let txs = transactions_in_dependency_order(txs)?;
        let mut live_pressure = self.start_live_pressure(&txs).await?;
        let required_outpoints: HashSet<(String, i32)> = txs
            .iter()
            .flat_map(|tx| {
                tx.with_normalized_missing_output_indexes()
                    .outputs
                    .iter()
                    .filter(|output| {
                        hex::decode(&output.script_public_key)
                            .is_ok_and(|script| is_p2sh_script_pubkey(&script))
                    })
                    .map(|output| (tx.transaction_id.to_ascii_lowercase(), output.index as i32))
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut total = PersistStats::default();
        let mut index = 0;
        let mut bulk_transactions = 0;
        let mut bulk_batches = 0;
        let mut bulk_elapsed_ms = 0;
        let mut max_bulk_elapsed_ms = 0;
        let mut bulk_lock_wait_us = 0;
        let mut max_bulk_lock_held_us = 0;
        let mut bulk_rejected = 0;
        let mut bulk_rejected_elapsed_ms = 0;
        let bulk_max_txs = self.generic_bulk_max_txs.unwrap_or_else(|| {
            std::env::var("TN12_GENERIC_BULK_MAX_TXS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(generic_bulk::DEFAULT_TXS)
                .clamp(2, generic_bulk::MAX_TXS)
        });
        // Reductions are shared by this whole source window. Never grow the
        // cap again until the caller supplies a fresh reconciled window.
        let mut effective_bulk_max_txs = bulk_max_txs;
        let mut budget_splits = 0usize;
        while index < txs.len() {
            if let Some(pressure) = live_pressure.as_mut() {
                pressure.refresh().await?;
            }
            if self.generic_bulk_persist && generic_bulk::is_writer_candidate(&txs[index], &self.decoders, self.native_genesis_bulk)
            {
                let end = (index + effective_bulk_max_txs).min(txs.len());
                let count = generic_bulk::writer_prefix_len(&txs[index..end], &self.decoders, self.native_genesis_bulk);
                // The generic SQL writer also accepts one ordinary transaction.
                // Keep dependency-boundary and odd-tail retries on that guarded
                // path instead of falling through to an unbudgeted scalar write.
                let minimum = if self.generic_writer_budget {
                    1
                } else {
                    generic_bulk::minimum_batch_len(&txs[index])
                };
                if count >= minimum {
                    let bulk_started = std::time::Instant::now();
                    let result = self
                        .try_persist_generic_batch(&txs[index..index + count])
                        .await;
                    let result = match result {
                        Err(error)
                            if self.generic_writer_budget
                                && error.downcast_ref::<TransientPersistError>().is_some_and(
                                    |e| e.kind == PersistTransientKind::WriterBudgetExceeded,
                                )
                                && count > 1
                                && budget_splits < 7 =>
                        {
                            effective_bulk_max_txs = (count / 2).max(1);
                            budget_splits += 1;
                            tracing::warn!(
                                event = "generic_writer_budget_split",
                                batch_transactions = txs.len(),
                                completed_transactions = index,
                                attempt_transactions = count,
                                next_batch_transactions = effective_bulk_max_txs,
                                budget_splits,
                                elapsed_ms = bulk_started.elapsed().as_millis(),
                                "generic writer rolled back; retrying smaller batch"
                            );
                            continue;
                        }
                        Err(error) => {
                            if self.generic_writer_budget {
                                let reason = if error
                                    .downcast_ref::<GenericWriteOutcomeUnknown>()
                                    .is_some()
                                {
                                    "unknown_transaction_outcome"
                                } else if error.downcast_ref::<TransientPersistError>().is_some_and(
                                    |e| e.kind == PersistTransientKind::WriterBudgetExceeded,
                                ) {
                                    "minimum_or_split_limit_exhausted"
                                } else {
                                    "database_or_evidence_error"
                                };
                                tracing::warn!(
                                    event = "generic_writer_window_retained",
                                    reason,
                                    batch_transactions = txs.len(),
                                    completed_transactions = index,
                                    attempt_transactions = count,
                                    budget_splits,
                                    elapsed_ms = bulk_started.elapsed().as_millis(),
                                    "generic writer stopped; retaining source window"
                                );
                            }
                            return Err(error);
                        }
                        Ok(result) => result,
                    };
                    if let Some(stats) = result {
                        bulk_lock_wait_us += stats.lock_wait_us;
                        max_bulk_lock_held_us = max_bulk_lock_held_us.max(stats.lock_held_us);
                        total.merge(stats.stats);
                        bulk_transactions += count;
                        bulk_batches += 1;
                        let elapsed_ms = bulk_started.elapsed().as_millis();
                        bulk_elapsed_ms += elapsed_ms;
                        max_bulk_elapsed_ms = max_bulk_elapsed_ms.max(elapsed_ms);
                        index += count;
                        continue;
                    }
                    if budget_splits > 0 {
                        tracing::warn!(
                            event = "generic_writer_window_retained",
                            reason = "eligibility_changed",
                            batch_transactions = txs.len(),
                            completed_transactions = index,
                            attempt_transactions = count,
                            budget_splits,
                            "generic eligibility changed; retaining source window"
                        );
                        return Err(TransientPersistError::writer_budget_exceeded())
                            .context("generic eligibility changed after a budget rollback; retain source window instead of scalar fallback");
                    }
                    bulk_rejected += 1;
                    bulk_rejected_elapsed_ms += bulk_started.elapsed().as_millis();
                }
            }
            let (stats, _) = self
                .persist_tx_inner(&txs[index], Some(&required_outpoints), false, None)
                .await?;
            total.merge(stats);
            index += 1;
        }
        if bulk_transactions > 0 || bulk_rejected > 0 {
            tracing::info!(
                bulk_transactions,
                bulk_batches,
                bulk_max_txs,
                effective_bulk_max_txs,
                budget_splits,
                bulk_elapsed_ms,
                max_bulk_elapsed_ms,
                bulk_lock_wait_us,
                max_bulk_lock_held_us,
                bulk_rejected,
                bulk_rejected_elapsed_ms,
                batch_transactions = txs.len(),
                "persisted generic P2SH transactions in bounded batches"
            );
        }

        if let Some(pressure) = live_pressure {
            pressure.finish().await;
        }
        Ok(total)
    }

    async fn revert_block(&self, block_hash: &[u8]) -> Result<RevertStats> {
        let mut results = self.revert_blocks_locked(&[block_hash.to_vec()]).await?;
        Ok(results.remove(0))
    }

    async fn revert_blocks(&self, block_hashes: &[Vec<u8>]) -> Result<Vec<RevertStats>> {
        self.revert_blocks_locked(block_hashes).await
    }

    async fn has_utxo(&self, txid_hex: &str, vout: i32) -> Result<bool> {
        let txid =
            hex::decode(txid_hex).with_context(|| format!("decoding outpoint txid {txid_hex}"))?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM covenant_utxos WHERE txid = $1 AND vout = $2)",
        )
        .bind(txid)
        .bind(vout)
        .fetch_one(&self.pool)
        .await
        .context("lookup covenant_utxos outpoint")?;
        Ok(exists)
    }

    async fn existing_utxos(&self, outpoints: &[(String, i32)]) -> Result<HashSet<(String, i32)>> {
        if outpoints.is_empty() {
            return Ok(HashSet::new());
        }

        let mut txids = Vec::with_capacity(outpoints.len());
        let mut vouts = Vec::with_capacity(outpoints.len());
        for (txid_hex, vout) in outpoints {
            txids.push(
                hex::decode(txid_hex)
                    .with_context(|| format!("decoding outpoint txid {txid_hex}"))?,
            );
            vouts.push(*vout);
        }

        let rows: Vec<(String, i32)> = sqlx::query_as(
            r#"SELECT encode(u.txid, 'hex'), u.vout
               FROM covenant_utxos u
               JOIN UNNEST($1::bytea[], $2::int4[]) AS wanted(txid, vout)
                 ON u.txid = wanted.txid AND u.vout = wanted.vout"#,
        )
        .bind(txids)
        .bind(vouts)
        .fetch_all(&self.pool)
        .await
        .context("lookup covenant_utxos outpoints")?;

        Ok(rows.into_iter().collect())
    }

    async fn conflicting_input_spends(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        let mut requested = std::collections::BTreeSet::new();
        for tx in txs.iter().filter(|tx| tx.is_accepted) {
            let incoming = hex::decode(&tx.transaction_id)
                .with_context(|| format!("decode live recovery transaction {}", tx.transaction_id))?;
            anyhow::ensure!(incoming.len() == 32, "invalid live recovery transaction ID");
            for input in &tx.inputs {
                let previous = hex::decode(&input.previous_outpoint_hash).with_context(|| {
                    format!("decode live recovery input {}", input.previous_outpoint_hash)
                })?;
                anyhow::ensure!(previous.len() == 32, "invalid live recovery input ID");
                let vout: i32 = input.previous_outpoint_index.parse()
                    .context("decode live recovery input index")?;
                anyhow::ensure!(vout >= 0, "negative live recovery input index");
                requested.insert((previous, vout, incoming.clone()));
            }
        }
        if requested.is_empty() {
            return Ok(Vec::new());
        }
        let mut previous_txids = Vec::with_capacity(requested.len());
        let mut previous_vouts = Vec::with_capacity(requested.len());
        let mut incoming_txids = Vec::with_capacity(requested.len());
        for (txid, vout, incoming) in requested {
            previous_txids.push(txid);
            previous_vouts.push(vout);
            incoming_txids.push(incoming);
        }
        let rows: Vec<(Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>)> = sqlx::query_as(
            "SELECT DISTINCT u.spent_by_txid,u.spent_block,b.blue_score \
             FROM UNNEST($1::bytea[],$2::int4[],$3::bytea[]) \
                  AS wanted(txid,vout,incoming_txid) \
             JOIN covenant_utxos u ON u.txid=wanted.txid AND u.vout=wanted.vout \
             LEFT JOIN blocks b ON b.hash=u.spent_block \
             WHERE u.status='spent' AND u.spent_by_txid IS DISTINCT FROM wanted.incoming_txid",
        )
        .bind(previous_txids)
        .bind(previous_vouts)
        .bind(incoming_txids)
        .fetch_all(&self.pool)
        .await
        .context("find conflicting persisted live input spends")?;
        let mut conflicts = Vec::with_capacity(rows.len());
        for (spender, block, score) in rows {
            let spender = spender.context("conflicting spent input has no spender")?;
            let block = block.context("conflicting spent input has no accepting block")?;
            let score = score.context("conflicting spent input has no indexed accepting block")?;
            anyhow::ensure!(spender.len() == 32 && block.len() == 32 && score >= 0,
                "invalid conflicting persisted input spend");
            conflicts.push(PersistedInputSpend {
                spender_txid: hex::encode(spender),
                block_hash: hex::encode(block),
                block_blue_score: score as u64,
            });
        }
        conflicts.sort();
        Ok(conflicts)
    }

    async fn recovery_block_impact(&self, block_hash: &str) -> Result<RecoveryBlockImpact> {
        self.load_recovery_impact(block_hash).await
    }

    async fn revert_recovery_blocks(&self, impacts: &[RecoveryBlockImpact]) -> Result<Vec<RevertStats>> {
        self.remove_recovery_impact(impacts).await
    }

    async fn indexed_block_transaction_ids(&self, block_hash: &str) -> Result<Vec<String>> {
        let block = hex::decode(block_hash).context("decode affected block hash")?;
        anyhow::ensure!(block.len() == 32, "invalid affected block hash");
        let descendants: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM covenant_utxos \
             WHERE created_block=$1 AND spent_block IS NOT NULL AND spent_block<>$1)",
        )
        .bind(&block)
        .fetch_one(&self.pool)
        .await
        .context("check removed block for indexed descendants")?;
        anyhow::ensure!(!descendants, "removed block has indexed descendant spends");
        let txids: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT txid FROM covenant_actions WHERE block_hash=$1 \
             UNION SELECT txid FROM covenant_utxos WHERE created_block=$1 \
             UNION SELECT spent_by_txid FROM covenant_utxos \
               WHERE spent_block=$1 AND spent_by_txid IS NOT NULL \
             UNION SELECT genesis_txid FROM covenants WHERE genesis_block=$1",
        )
        .bind(&block)
        .fetch_all(&self.pool)
        .await
        .context("collect indexed transactions in removed block")?;
        anyhow::ensure!(txids.len() <= 256, "too many indexed transactions in removed block");
        txids.into_iter().map(|txid| {
            anyhow::ensure!(txid.len() == 32, "invalid indexed transaction ID");
            Ok(hex::encode(txid))
        }).collect()
    }

    async fn stale_persisted_acceptances(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        let mut ids = Vec::new();
        let mut hashes = Vec::new();
        for tx in txs.iter().filter(|tx| tx.is_accepted) {
            let id = hex::decode(&tx.transaction_id).context("decode retained transaction ID")?;
            let hash = hex::decode(tx.accepting_block_hash.as_deref().context("missing retained accepting block")?)
                .context("decode retained accepting block")?;
            anyhow::ensure!(id.len() == 32 && hash.len() == 32,
                "invalid retained acceptance identity");
            ids.push(id);
            hashes.push(hash);
        }
        if ids.is_empty() { return Ok(Vec::new()); }
        let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            "WITH wanted AS (SELECT * FROM UNNEST($1::bytea[],$2::bytea[]) AS w(txid,new_hash)), \
             old AS ( \
               SELECT a.txid,a.block_hash FROM covenant_actions a JOIN wanted w ON a.txid=w.txid WHERE a.block_hash<>w.new_hash \
               UNION SELECT u.txid,u.created_block FROM covenant_utxos u JOIN wanted w ON u.txid=w.txid WHERE u.created_block<>w.new_hash \
               UNION SELECT c.genesis_txid,c.genesis_block FROM covenants c JOIN wanted w ON c.genesis_txid=w.txid WHERE c.genesis_block<>w.new_hash \
             ) SELECT DISTINCT old.txid,old.block_hash,b.blue_score FROM old JOIN blocks b ON b.hash=old.block_hash",
        )
        .bind(ids).bind(hashes)
        .fetch_all(&self.pool).await
        .context("find stale persisted live acceptances")?;
        let mut conflicts = Vec::with_capacity(rows.len());
        for (txid, block, score) in rows {
            anyhow::ensure!(txid.len() == 32 && block.len() == 32 && score >= 0,
                "invalid stale persisted acceptance");
            conflicts.push(PersistedInputSpend {
                spender_txid: hex::encode(txid),
                block_hash: hex::encode(block),
                block_blue_score: score as u64,
            });
        }
        conflicts.sort();
        Ok(conflicts)
    }

    async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
        self.require_rest_guard_transactions(std::slice::from_ref(tx))?;
        self.persist_tx_inner(tx, None, false, None)
            .await
            .map(|(stats, _)| stats)
    }
    async fn reconcile_accepting_block(
        &self,
        proof: &CanonicalBlockReplacement,
    ) -> Result<AcceptanceReconciliationStats> {
        PgPersister::reconcile_accepting_block(self, proof).await
    }
}

impl PgPersister {
    /// Explicit decoding replay bypasses normal "already indexed" filtering.
    /// The retained body, current canonical acceptance and dependency order are
    /// checked under the same writer lock as decoded effects and resolution.
    pub async fn replay_deferred_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
        anyhow::ensure!(tx.is_accepted,"deferred replay requires current acceptance");
        self.persist_tx_inner(tx,None,true,None).await.map(|(stats,_)|stats)
    }

    /// The caller must first compare this body with a fresh source response.
    /// Persistence and its replay checkpoint commit in one writer transaction.
    pub async fn replay_paged_recovery_tx(
        &self,
        owner: &PagedRecoveryOwner,
        tx: &RestTransaction,
    ) -> Result<PersistStats> {
        anyhow::ensure!(tx.is_accepted, "paged replay requires current acceptance");
        self.persist_tx_inner(tx, None, false, Some(owner))
            .await
            .map(|(stats, _)| stats)
    }

    /// Complete only after a second fresh, mature source observation made after
    /// replay. A concurrent reorg or another opaque write invalidates the marker.
    pub async fn confirm_deferred_decode(&self, proof: &crate::deferred_decode::CanonicalDecodeProof) -> Result<()> {
        proof.ensure_fresh()?;
        let mut conn=self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        if let Err(error)=proof.ensure_fresh() {
            conn.rollback().await.context("rollback expired deferred confirmation")?;
            return Err(error);
        }
        let changed=sqlx::query("UPDATE indexer_deferred_decodes d SET status='resolved',resolved_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint             FROM blocks b WHERE b.hash=d.block_hash AND b.is_chain_block AND d.txid=$1 AND d.block_hash=$2             AND d.status='pending' AND d.decoded_at_ms IS NOT NULL AND d.decoded_at_ms<=$3")
            .bind(proof.txid()).bind(proof.block_hash()).bind(proof.observed_at_ms()).execute(&mut *conn).await?.rows_affected();
        if changed!=1 {
            conn.rollback().await.context("rollback rejected deferred confirmation")?;
            anyhow::bail!("deferred replay changed, was orphaned, or has not passed post-write verification");
        }
        conn.commit().await?;
        Ok(())
    }

    async fn persist_tx_inner(
        &self,
        tx: &RestTransaction,
        required_outpoints: Option<&HashSet<(String, i32)>>,
        replay_deferred: bool,
        recovery_owner: Option<&PagedRecoveryOwner>,
    ) -> Result<(PersistStats, bool)> {
        self.require_rest_guard_transactions(std::slice::from_ref(tx))?;
        if !tx.is_accepted {
            anyhow::ensure!(recovery_owner.is_none(), "rejected paged replay body");
            return Ok((PersistStats::default(), false));
        }
        let mut conn = self.pool.begin().await.context("begin persist tx")?;
        Self::set_persist_query_limits(&mut conn).await?;
        self.acquire_recovery_writer_lock(&mut conn, recovery_owner).await?;
        if let Some(owner) = recovery_owner {
            if !owner.prepare_replay(&mut conn, tx).await? {
                conn.commit().await?;
                return Ok((PersistStats::default(), false));
            }
        }
        sqlx::query("SAVEPOINT application_decode").execute(&mut *conn).await?;
        let result = self.persist_tx_effects(&mut conn, tx, required_outpoints, replay_deferred, None).await;
        let outcome = match result {
            Err(error) if !replay_deferred && error.downcast_ref::<tn12_indexer_decoder::InterpretationFailure>().is_some()
                && error.downcast_ref::<tn12_indexer_decoder::IntegrityFailure>().is_none() => {
                sqlx::query("ROLLBACK TO SAVEPOINT application_decode").execute(&mut *conn).await
                    .context("rollback failed application interpretation")?;
                let reason = format!("{error:#}");
                // Fresh accumulators, same transaction and writer ownership.
                self.persist_tx_effects(&mut conn, tx, required_outpoints, false, Some(&reason)).await
            }
            other => other,
        };
        let (stats, refresh, claims) = match outcome {
            Ok(value) => value,
            Err(error) => {
                conn.rollback().await.context("rollback rejected transaction")?;
                return Err(error);
            }
        };
        sqlx::query("RELEASE SAVEPOINT application_decode").execute(&mut *conn).await?;
        if let Some(owner) = recovery_owner {
            owner.checkpoint_replay(&mut conn, tx).await?;
        }
        conn.commit().await.context("commit persist tx")?;
        for (covenant_id, claim) in claims {
            self.retry_deploy_payload_claim_after_commit(&covenant_id, &claim).await;
        }
        Ok((stats, refresh))
    }

    async fn persist_tx_effects(
        &self,
        mut conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        source_body: &RestTransaction,
        required_outpoints: Option<&HashSet<(String, i32)>>,
        replay_deferred: bool,
        forced_reason: Option<&str>,
    ) -> Result<(PersistStats, bool, Vec<(Vec<u8>, claim::ClaimedDeployment)>)> {
        let normalized_tx = source_body.with_normalized_missing_output_indexes();
        let tx = &normalized_tx;
        let mut stats = PersistStats::default();
        let (deferred_reason, deferred_families) = deferred_decode::prepare(
            &mut **conn, tx, &self.decoders, replay_deferred, forced_reason,
        ).await?;
        let opaque=deferred_reason.is_some();

        sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair', 'on', TRUE)")
            .execute(&mut **conn)
            .await
            .context("defer covenant summary repair")?;
        let mut kcc20_output_states: HashMap<i32, (Vec<u8>, Value)> = HashMap::new();
        let mut verified_fee_ticket_genesis: Option<(Vec<u8>, Value)> = None;
        let mut kcom_initializer_vault_output_indexes = HashSet::new();
        let mut fomo_output_states: HashMap<i32, (Vec<u8>, Value)> = HashMap::new();
        let mut snapshot_output_states: HashMap<i32, (Vec<u8>, Value)> = HashMap::new();
        let mut kcc20_touched: HashSet<Vec<u8>> = HashSet::new();
        let mut covenant_summaries_touched: HashSet<Vec<u8>> = HashSet::new();
        let mut pending_kcc20_orderbook_merges = Vec::new();
        let mut pending_kcom_vault_opens = Vec::new();
        let mut pending_kcom_vault_funds = Vec::new();
        let mut pending_kcom_vault_seals = Vec::new();
        let mut pending_kcom_settlement_collections = Vec::new();
        let mut pending_kcom_settlement_claims = Vec::new();
        let mut pending_kcom_activations = Vec::new();
        let mut pending_kcom_recoveries = Vec::new();
        let mut authenticated_kcom_positions = Vec::new();
        let mut pending_kcc20_fee_groups: Vec<(Vec<u8>, String, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_recipients: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_accounts: Vec<(usize, Vec<u8>, String, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_bindings: Vec<(usize, Vec<u8>, Value, Vec<u8>, kcc20_fee_v1::FeeMarketWrapperVersion)> = Vec::new();
        let mut pending_kcc20_fee_market_wraps: Vec<(usize, Vec<u8>, Value, Vec<u8>, kcc20_fee_v1::FeeMarketWrapperVersion)> = Vec::new();
        let mut pending_kcc20_fee_market_merges: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_unwraps: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_asks: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_ask_cancels: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_bids: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_crosses: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_buys: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut pending_kcc20_fee_market_sells: Vec<(usize, Vec<u8>, Value, Vec<u8>)> = Vec::new();
        let mut fee_market_ask_states_by_input: HashMap<usize, Value> = HashMap::new();
        let mut fee_market_holder_states_by_input: HashMap<usize, Value> = HashMap::new();
        let mut fee_market_wrapper_states_by_input: HashMap<usize, (Value, kcc20_fee_v1::FeeMarketWrapperVersion)> = HashMap::new();
        let mut fee_market_bid_states_by_input: HashMap<usize, Value> = HashMap::new();
        let mut fee_receipt_states_by_input: HashMap<usize, Value> = HashMap::new();
        let mut pending_kcc20_fee_claims: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut snapshot_start_token: Option<SnapshotStartKcc20Projection> = None;
        let mut deploy_claims_seen: HashSet<Vec<u8>> = HashSet::new();
        let mut post_commit_payload_claims: Vec<(Vec<u8>, claim::ClaimedDeployment)> = Vec::new();
        let mut refresh_kcc20_markets = false;
        let mut persisted_change = false;
        let claim_from_payload: Option<claim::ClaimedDeployment> = if opaque { None } else {
            tx.payload.as_deref().and_then(claim::parse_payload_envelope)
        };
        let mut wrapper_reveal_is_action = false;
        let mut wrapper_controller_output_indexes: HashSet<i32> = HashSet::new();

        let accepting = tx.accepting_block_hash.as_deref().ok_or_else(|| {
            anyhow::anyhow!("tx {} has no accepting_block_hash", tx.transaction_id)
        })?;
        let accepting_hash = hex::decode(accepting)
            .with_context(|| format!("decoding accepting_block_hash for {}", tx.transaction_id))?;
        let blue_score = tx.accepting_block_blue_score.unwrap_or(0) as i64;
        let block_time = tx.accepting_block_time.unwrap_or(tx.block_time) as i64;

        let spent_by_txid = hex::decode(&tx.transaction_id)
            .with_context(|| format!("decoding txid {}", tx.transaction_id))?;
        let acceptance =
            Self::check_transaction_acceptance(&mut conn, &spent_by_txid, &accepting_hash).await;
        if acceptance
            .as_ref()
            .err()
            .is_some_and(|error| error.downcast_ref::<AcceptanceConflict>().is_some())
        {
            Self::check_conflicting_output_content(&mut conn, tx).await?;
        }
        acceptance?;

        let r = sqlx::query(
            r#"INSERT INTO blocks
               (hash, blue_score, daa_score, parent_hashes, timestamp_ms, is_chain_block, indexed_at_ms)
               VALUES ($1, $2, 0, ARRAY[]::BYTEA[], $3, TRUE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
               ON CONFLICT (hash) DO NOTHING"#,
        )
        .bind(&accepting_hash)
        .bind(blue_score)
        .bind(block_time)
        .execute(&mut **conn)
        .await
        .context("insert block")?;
        stats.blocks_inserted += r.rows_affected();

        let mut spent_covenant_ids_by_input: HashMap<usize, Vec<u8>> = HashMap::new();

        for (input_index, input) in tx.inputs.iter().enumerate() {
            let prev_txid = hex::decode(&input.previous_outpoint_hash).with_context(|| {
                format!("decoding prev outpoint {}", input.previous_outpoint_hash)
            })?;
            let prev_vout: i32 = input.previous_outpoint_index.parse().unwrap_or(0);
            let spent_row: Option<(Vec<u8>, String)> = sqlx::query_as(
                r#"UPDATE covenant_utxos
                   SET status = 'spent', spent_block = $1, spent_by_txid = $2
                   WHERE txid = $3 AND vout = $4 AND status = 'active'
                   RETURNING covenant_id, address"#,
            )
            .bind(&accepting_hash)
            .bind(&spent_by_txid)
            .bind(&prev_txid)
            .bind(prev_vout)
            .fetch_optional(&mut **conn)
            .await
            .map_err(|error| classify_persist_sqlx_error("mark utxo spent", error))?;
            let row: Option<(Vec<u8>, String, bool)> =
                if let Some((covenant_id, address)) = spent_row {
                    Some((covenant_id, address, true))
                } else {
                    let existing = sqlx::query_as::<
                        _,
                        (Vec<u8>, String, String, Option<Vec<u8>>, Option<Vec<u8>>),
                    >(
                        r#"SELECT covenant_id, address, status, spent_by_txid, spent_block
                       FROM covenant_utxos
                       WHERE txid = $1 AND vout = $2
                       LIMIT 1"#,
                    )
                    .bind(&prev_txid)
                    .bind(prev_vout)
                    .fetch_optional(&mut **conn)
                    .await
                    .context("lookup existing input covenant utxo")?;
                    if let Some((_, _, status, spender, block)) = &existing {
                        if status == "spent" {
                            anyhow::ensure!(
                                spender.as_ref() == Some(&spent_by_txid),
                                "input was spent by a different transaction"
                            );
                            let old = block
                                .as_ref()
                                .context("spent input has no accepting block")?;
                            if old != &accepting_hash {
                                return Err(AcceptanceConflict::new(
                                    &spent_by_txid,
                                    old,
                                    &accepting_hash,
                                )
                                .into());
                            }
                        }
                    }
                    existing.map(|(covenant_id, address, _, _, _)| (covenant_id, address, false))
                };
            if row.is_none() && tx.needs_input_identity(input) {
                return Err(identity::MissingIdentityDependency {
                    txid: input.previous_outpoint_hash.clone(), vout: prev_vout,
                }.into());
            }
            if row.is_none()
                && required_outpoints.is_some_and(|required| {
                    required
                        .contains(&(input.previous_outpoint_hash.to_ascii_lowercase(), prev_vout))
                })
            {
                anyhow::bail!(
                    "in-batch P2SH source output missing before spend: {}:{}",
                    input.previous_outpoint_hash,
                    prev_vout
                );
            }
            if let Some((covenant_id, input_address, spent_now)) = row {
                spent_covenant_ids_by_input.insert(input_index, covenant_id.clone());
                if spent_now {
                    stats.utxos_spent += 1;
                    persisted_change = true;
                    covenant_summaries_touched.insert(covenant_id.clone());
                }
                let inputs_json = serde_json::json!({
                    "previousOutpoint": {
                        "hash": input.previous_outpoint_hash,
                        "index": prev_vout,
                    },
                    "address": input_address,
                });

                // Decode the reveal script (last push in signature_script) to
                // identify the template and extract the entrypoint + decoded
                // constructor args. Update covenants row in the same tx so
                // future reads see template_name populated.
                let sig_script = hex::decode(&input.signature_script).unwrap_or_default();
                let reveal = extract_last_push(&sig_script);
                let mut entrypoint: Option<String> = None;
                let mut decoded_args: Option<Value> = None;
                let mut is_kcom_action = false;
                if let Some(reveal) = reveal.as_ref() {
                    if let Some(classification) =
                        (!opaque).then(|| classify_reveal_checked(&self.decoders, &sig_script, reveal)).transpose()?.flatten()
                    {
                        if is_kcc20_template(&classification.template_name) {
                            refresh_kcc20_markets = true;
                        }
                        entrypoint = classification.entrypoint.clone();
                        decoded_args = Some(classification.args.clone());
                        is_kcom_action = classification.template_name.starts_with("KCOM");
                        if classification.template_name == "KaspaFomoRound" {
                            if let Some(action_args) = tn12_indexer_decoder::interpretation("kaspa_fomo_round::decode_action_args", kaspa_fomo_round::decode_action_args(&sig_script))?
                            {
                                decoded_args = Some(action_args);
                            }
                        }

                        if classification.template_name == "KCC20SnapshotController" {
                            let input_state =
                                tn12_indexer_decoder::interpretation("kcc20_snapshot_controller::decode_reveal_state_value", kcc20_snapshot_controller::decode_reveal_state_value(reveal))
                                    .context("decode snapshot controller input state")?;
                            let result = sqlx::query(
                                r#"UPDATE covenant_utxos
                                   SET state = $1
                                   WHERE txid = $2 AND vout = $3
                                     AND state IS DISTINCT FROM $1"#,
                            )
                            .bind(&input_state)
                            .bind(&prev_txid)
                            .bind(prev_vout)
                            .execute(&mut **conn)
                            .await
                            .context("store snapshot controller spent input state")?;
                            persisted_change |= result.rows_affected() > 0;

                            if let Some(transition) =
                                kcc20_snapshot_controller::decode_claim_transition(
                                    &sig_script,
                                    reveal,
                                )
                                .context("decode snapshot controller claim transition")?
                            {
                                merge_json_object(&mut decoded_args, transition.clone());
                                if let Some((output_index, next_state)) =
                                    snapshot_controller_transition_successor(
                                        tx,
                                        input_index,
                                        &covenant_id,
                                        &transition,
                                    )?
                                {
                                    snapshot_output_states
                                        .insert(output_index, (covenant_id.clone(), next_state));
                                }
                            }
                        }
                        if classification.template_name == "KCC20SnapshotBootstrap" {
                            if let Some(start) = kcc20_snapshot_bootstrap::decode_bootstrap_action(
                                &sig_script,
                                reveal,
                            )
                            .context("decode signerless snapshot start")?
                            {
                                let (template_prefix, template_suffix) =
                                    kcc20_snapshot_bootstrap::decode_bootstrap_kcc20_template_parts(
                                        &sig_script,
                                        reveal,
                                    )?
                                    .context("snapshot start is missing its KCC20 template witness")?;
                                let projection = project_snapshot_start_kcc20(
                                    tx,
                                    &start,
                                    claim_from_payload.as_ref(),
                                    &template_prefix,
                                    &template_suffix,
                                )
                                .context("project signerless snapshot KCC20 genesis")?;
                                if projection.claim_source == "snapshot-start"
                                    && claim_from_payload
                                        .as_ref()
                                        .is_some_and(|claim| claim.tmpl == "KCC20")
                                {
                                    tracing::warn!(
                                        transaction_id = %tx.transaction_id,
                                        "ignored an invalid snapshot KCC20 metadata opening"
                                    );
                                }
                                if snapshot_start_token
                                    .as_ref()
                                    .is_some_and(|current| current.token_id != projection.token_id)
                                {
                                    anyhow::bail!(
                                        "transaction contains conflicting snapshot start token projections"
                                    );
                                }
                                for (output_index, state) in &projection.output_states {
                                    kcc20_output_states.insert(
                                        *output_index,
                                        (projection.token_id.clone(), state.clone()),
                                    );
                                }
                                kcc20_touched.insert(projection.token_id.clone());
                                snapshot_start_token = Some(projection);
                                merge_json_object(&mut decoded_args, start);
                            }
                        }
                        let classification_backfilled = Self::backfill_classification_best_effort(
                            &mut conn,
                            &covenant_id,
                            &classification.template_name,
                            &classification.args,
                            classification.kind,
                        )
                        .await?;
                        persisted_change |= classification_backfilled;

                        if matches!(classification.entrypoint.as_deref(),
                            Some("sellIntoBids" | "buyAsks" | "crossWithBid"))
                            && matches!(classification.template_name.as_str(),
                                "KCC20OrderbookFeeHolderV1" | "KCC20OrderbookFeeAskV1")
                        {
                            pending_kcc20_fee_groups.push((
                                sig_script.clone(),
                                classification.entrypoint.clone().unwrap(),
                                classification.args.clone(),
                                covenant_id.clone(),
                            ));
                        }
                        if classification.template_name == "KCC20FeeRecipientV1"
                            && classification.entrypoint.as_deref() == Some("approveFeeAccountAction")
                            && classification.args["roleName"] == "recipient"
                        {
                            pending_kcc20_fee_recipients.push((input_index, sig_script.clone(),
                                classification.args.clone(), covenant_id.clone()));
                        }
                        if classification.template_name == "KCC20FeeEscrowV1"
                            && matches!(classification.entrypoint.as_deref(),
                                Some("bindMarket" | "authorize"))
                            && classification.args["roleName"] == "account"
                        {
                            pending_kcc20_fee_accounts.push((
                                input_index, sig_script.clone(),
                                classification.entrypoint.clone().unwrap(),
                                classification.args.clone(), covenant_id.clone(),
                            ));
                        }
                        if matches!(classification.template_name.as_str(),
                            "KCC20WrapperFeeV1" | "KCC20WrapperFeeV2" | "KCC20WrapperFeeArgentV1" | "KCC20WrapperFeeArgentV2")
                            && classification.entrypoint.as_deref() == Some("bindMarket")
                        {
                            pending_kcc20_fee_market_bindings.push((
                                input_index,
                                sig_script.clone(),
                                classification.args.clone(),
                                covenant_id.clone(),
                                kcc20_fee_v1::FeeMarketWrapperVersion::from_template_name(&classification.template_name)
                                    .context("unsupported fee wrapper version")?,
                            ));
                        }
                        if matches!(classification.template_name.as_str(),
                            "KCC20WrapperFeeV1" | "KCC20WrapperFeeV2" | "KCC20WrapperFeeArgentV1" | "KCC20WrapperFeeArgentV2")
                            && classification.entrypoint.as_deref() == Some("wrap")
                        {
                            pending_kcc20_fee_market_wraps.push((
                                input_index, sig_script.clone(), classification.args.clone(),
                                covenant_id.clone(),
                                kcc20_fee_v1::FeeMarketWrapperVersion::from_template_name(&classification.template_name)
                                    .context("unsupported fee wrapper version")?,
                            ));
                        }
                        if matches!(classification.template_name.as_str(),
                            "KCC20WrapperFeeV1" | "KCC20WrapperFeeV2" | "KCC20WrapperFeeArgentV1" | "KCC20WrapperFeeArgentV2")
                        {
                            fee_market_wrapper_states_by_input.insert(input_index, (
                                classification.args.clone(),
                                kcc20_fee_v1::FeeMarketWrapperVersion::from_template_name(&classification.template_name)
                                    .context("unsupported fee wrapper version")?,
                            ));
                        }
                        if classification.template_name == "KCC20OrderbookFeeHolderV1" {
                            fee_market_holder_states_by_input
                                .insert(input_index, classification.args.clone());
                            if classification.entrypoint.as_deref() == Some("createAsk") {
                                pending_kcc20_fee_market_asks.push((
                                    input_index, sig_script.clone(), classification.args.clone(),
                                    covenant_id.clone(),
                                ));
                            } else if classification.entrypoint.as_deref() == Some("mergeHolders") {
                                pending_kcc20_fee_market_merges.push((input_index, covenant_id.clone()));
                            } else if classification.entrypoint.as_deref() == Some("unwrap") {
                                pending_kcc20_fee_market_unwraps.push((
                                    input_index, sig_script.clone(), classification.args.clone(),
                                    covenant_id.clone(),
                                ));
                            }
                        }
                        if classification.template_name == "KCC20OrderbookFeeRootV1"
                            && classification.entrypoint.as_deref() == Some("createBid")
                        {
                            pending_kcc20_fee_market_bids.push((
                                input_index, sig_script.clone(), classification.args.clone(),
                                covenant_id.clone(),
                            ));
                        }
                        if classification.template_name == "KCC20OrderbookFeeAskV1" {
                            fee_market_ask_states_by_input
                                .insert(input_index, classification.args.clone());
                            if classification.entrypoint.as_deref() == Some("buyAsks") {
                                pending_kcc20_fee_market_buys.push((
                                    input_index,
                                    sig_script.clone(),
                                    classification.args.clone(),
                                    covenant_id.clone(),
                                ));
                            } else if classification.entrypoint.as_deref() == Some("crossWithBid") {
                                pending_kcc20_fee_market_crosses.push((input_index, sig_script.clone(), covenant_id.clone()));
                            } else if classification.entrypoint.as_deref() == Some("cancelAsk") {
                                pending_kcc20_fee_market_ask_cancels.push((
                                    input_index, sig_script.clone(), classification.args.clone(),
                                    covenant_id.clone(),
                                ));
                            }
                        }
                        if classification.template_name == "KCC20OrderbookFeeBidV1" {
                            fee_market_bid_states_by_input.insert(input_index, classification.args.clone());
                        }
                        if classification.template_name == "KCC20OrderbookFeeHolderV1"
                            && classification.entrypoint.as_deref() == Some("sellIntoBids")
                        {
                            pending_kcc20_fee_market_sells.push((
                                input_index, sig_script.clone(), classification.args.clone(),
                                covenant_id.clone(),
                            ));
                        }
                        if classification.template_name == "KCC20FeeEscrowV1"
                            && classification.args["roleName"] == "receipt"
                        {
                            fee_receipt_states_by_input.insert(input_index, classification.args.clone());
                            if classification.entrypoint.as_deref() == Some("claim") {
                                pending_kcc20_fee_claims.push((
                                    input_index, sig_script.clone(), covenant_id.clone(),
                                ));
                            }
                        }

                        if matches!(
                            classification.template_name.as_str(),
                            "KCC20FeeEscrowV1"
                                | "KCC20FeeRecipientV1"
                                | "KCC20OrderbookFeeRootV1"
                                | "KCC20OrderbookFeeHolderV1"
                                | "KCC20OrderbookFeeAskV1"
                                | "KCC20OrderbookFeeBidV1"
                                | "KCC20WrapperFeeV1" | "KCC20WrapperFeeV2"
                                | "KCC20WrapperFeeArgentV1"
                                | "KCC20WrapperFeeArgentV2"
                        ) {
                            // The accepted spend reveals the exact script and state
                            // committed by this outpoint. Keep that evidence on the
                            // spent UTXO for later fee and reorg projections. An
                            // output with no authenticated reveal stays unverified.
                            let result = sqlx::query(
                                r#"UPDATE covenant_utxos
                                   SET state = $1
                                   WHERE txid = $2 AND vout = $3
                                     AND state IS NULL"#,
                            )
                            .bind(&classification.args)
                            .bind(&prev_txid)
                            .bind(prev_vout)
                            .execute(&mut **conn)
                            .await
                            .context("store versioned fee covenant spent input state")?;
                            persisted_change |= result.rows_affected() > 0;
                            if result.rows_affected() == 0 {
                                let stored: Option<Option<Value>> = sqlx::query_scalar(
                                    "SELECT state FROM covenant_utxos WHERE txid = $1 AND vout = $2",
                                )
                                .bind(&prev_txid)
                                .bind(prev_vout)
                                .fetch_optional(&mut **conn)
                                .await
                                .context("read previously recorded fee input state")?;
                                anyhow::ensure!(
                                    stored == Some(Some(classification.args.clone())),
                                    "versioned fee input state disagrees with authenticated reveal"
                                );
                            }
                        }

                        if classification.template_name == "KCC20" {
                            let action_args = tn12_indexer_decoder::interpretation(
                                "standard_kcc20_action", kcc20_standard::decode_action_args_for_reveal(&sig_script, reveal),
                            )?;
                            if let Some(action_args) = action_args.as_ref() {
                                merge_json_object(&mut decoded_args, action_args.clone());
                            }
                            merge_json_object(
                                &mut decoded_args,
                                serde_json::json!({"inputIndex": input_index.to_string()}),
                            );

                            let input_state = tn12_indexer_decoder::interpretation("kcc20_standard::decode_reveal_state", kcc20_standard::decode_reveal_state(reveal))?;
                             {
                                let state = serde_json::to_value(&input_state)
                                    .context("serialize KCC20 input state")?;
                                let extension_matches = if let Some(expected_extension) =
                                    action_args
                                        .as_ref()
                                        .and_then(|args| args.get("extensionCommitment"))
                                        .and_then(Value::as_str)
                                {
                                    let actual_extension =
                                        state.get("extensionCommitment").and_then(Value::as_str);
                                    actual_extension.is_some_and(|actual| {
                                        actual.eq_ignore_ascii_case(expected_extension)
                                    })
                                } else {
                                    true
                                };
                                if extension_matches {
                                    let result = sqlx::query(
                                        r#"UPDATE covenant_utxos
                                           SET state = COALESCE(state, $1)
                                           WHERE txid = $2 AND vout = $3
                                             AND state IS NULL"#,
                                    )
                                    .bind(&state)
                                    .bind(&prev_txid)
                                    .bind(prev_vout)
                                    .execute(&mut **conn)
                                    .await
                                    .context("store KCC20 spent input state")?;
                                    persisted_change |= result.rows_affected() > 0;
                                    kcc20_touched.insert(covenant_id.clone());
                                } else {
                                    tracing::warn!(
                                        transaction_id = %tx.transaction_id,
                                        input_index,
                                        "standard KCC20 extension opening does not match input state; skipping enrichment"
                                    );
                                }
                            }

                            if let Some(action_args) = action_args.as_ref() {
                                if let Some(outputs) =
                                    action_args.get("outputStates").and_then(Value::as_array)
                                {
                                    for output in outputs {
                                        if let (Some(output_index), Some(state)) = (
                                            json_i32(output.get("outputIndex")),
                                            output.get("state").cloned(),
                                        ) {
                                            kcc20_output_states
                                                .insert(output_index, (covenant_id.clone(), state));
                                        } else {
                                            return Err(anyhow::anyhow!(
                                                tn12_indexer_decoder::InterpretationFailure("malformed standard KCC20 output state")
                                            ));
                                        }
                                    }
                                }

                                if let Some(next_states) =
                                    action_args.get("nextStates").and_then(Value::as_array)
                                {
                                    let family_outputs = tx
                                        .outputs
                                        .iter()
                                        .filter(|output| {
                                            output
                                                .canonical_covenant_id()
                                                .and_then(|id| hex::decode(id).ok())
                                                .as_deref()
                                                == Some(covenant_id.as_slice())
                                        })
                                        .collect::<Vec<_>>();
                                    if family_outputs.len() != next_states.len() {
                                        tracing::warn!(
                                            transaction_id = %tx.transaction_id,
                                            input_index,
                                            next_state_count = next_states.len(),
                                            family_output_count = family_outputs.len(),
                                            "standard KCC20 state/output count mismatch; skipping enrichment"
                                        );
                                    } else {
                                        for (output, state) in
                                            family_outputs.into_iter().zip(next_states)
                                        {
                                            kcc20_output_states.insert(
                                                output.index as i32,
                                                (covenant_id.clone(), state.clone()),
                                            );
                                        }
                                    }
                                }
                            }
                            kcc20_touched.insert(covenant_id.clone());
                        }

                        if classification.template_name == "KaspaFomoRound" {
                            let state = tn12_indexer_decoder::interpretation("kaspa_fomo_round::decode_reveal_state_value", kaspa_fomo_round::decode_reveal_state_value(reveal))?;
                             {
                                let result = sqlx::query(
                                    r#"UPDATE covenant_utxos
                                       SET state = COALESCE(state, $1)
                                       WHERE txid = $2 AND vout = $3
                                         AND state IS NULL"#,
                                )
                                .bind(&state)
                                .bind(&prev_txid)
                                .bind(prev_vout)
                                .execute(&mut **conn)
                                .await
                                .context("store KaspaFomoRound spent input state")?;
                                persisted_change |= result.rows_affected() > 0;
                            }

                            if let Some(outputs) = tn12_indexer_decoder::interpretation("kaspa_fomo_round::decode_output_state_values", kaspa_fomo_round::decode_output_state_values(&sig_script, reveal))?
                            {
                                let inferred_changes = upsert_inferred_kcc20_outputs(
                                    &mut conn,
                                    tx,
                                    &accepting_hash,
                                    &covenant_id,
                                    &outputs,
                                )
                                .await
                                .context("upsert inferred KaspaFomoRound output states")?;
                                persisted_change |= inferred_changes > 0;
                                for (output_index, state) in outputs {
                                    fomo_output_states
                                        .insert(output_index, (covenant_id.clone(), state));
                                }
                            }
                        }

                        if classification.template_name == "KCC20Orderbook" {
                            if let Some(action_args) = tn12_indexer_decoder::interpretation("kcc20_orderbook::decode_action_args", kcc20_orderbook::decode_action_args(&sig_script))?
                            {
                                merge_json_object(&mut decoded_args, action_args);
                            }
                            // The wrapped input shares the wrapper covenant
                            // family, but its structural transaction index is
                            // still the exact linkage used by wrapper actions.
                            merge_json_object(
                                &mut decoded_args,
                                serde_json::json!({"inputIndex": input_index.to_string()}),
                            );

                            let state = tn12_indexer_decoder::interpretation("kcc20_orderbook::decode_reveal_state_value", kcc20_orderbook::decode_reveal_state_value(reveal))?;
                             {
                                let result = sqlx::query(
                                    r#"UPDATE covenant_utxos
                                       SET state = COALESCE(state, $1)
                                       WHERE txid = $2 AND vout = $3
                                         AND state IS NULL"#,
                                )
                                .bind(&state)
                                .bind(&prev_txid)
                                .bind(prev_vout)
                                .execute(&mut **conn)
                                .await
                                .context("store KCC20Orderbook spent input state")?;
                                persisted_change |= result.rows_affected() > 0;
                                kcc20_touched.insert(covenant_id.clone());
                            }

                            if let Some(outputs) = tn12_indexer_decoder::interpretation("kcc20_orderbook::decode_output_state_values", kcc20_orderbook::decode_output_state_values(&sig_script, reveal))?
                            {
                                let inferred_changes = upsert_inferred_kcc20_outputs(
                                    &mut conn,
                                    tx,
                                    &accepting_hash,
                                    &covenant_id,
                                    &outputs,
                                )
                                .await
                                .context("upsert inferred KCC20Orderbook output states")?;
                                persisted_change |= inferred_changes > 0;
                                for (output_index, state) in outputs {
                                    kcc20_output_states
                                        .insert(output_index, (covenant_id.clone(), state));
                                }
                                kcc20_touched.insert(covenant_id.clone());
                            }

                            match tn12_indexer_decoder::interpretation("kcc20_orderbook::decode_primary_merge_request", kcc20_orderbook::decode_primary_merge_request(&sig_script)) {
                                Ok(Some(_)) => pending_kcc20_orderbook_merges.push((
                                    input_index,
                                    sig_script.clone(),
                                    reveal.clone(),
                                    covenant_id.clone(),
                                )),
                                Ok(None) => {}
                                Err(error) => {
                                    return Err(error).with_context(|| {
                                        format!(
                                            "decode KCC20Orderbook merge for tx {} input {}",
                                            tx.transaction_id, input_index
                                        )
                                    });
                                }
                            }
                        }

                        if classification.template_name == "KCC20Wrapper" {
                            if let Some(action_args) = tn12_indexer_decoder::interpretation("kcc20_wrapper::decode_action_args", kcc20_wrapper::decode_action_args(&sig_script))?
                            {
                                wrapper_reveal_is_action = true;
                                let output_index = action_args
                                    .get("wrapperOutputIndex")
                                    .and_then(Value::as_str)
                                    .context("wrapper action has no continuation output index")?
                                    .parse::<i32>()
                                    .context("invalid wrapper continuation output index")?;
                                wrapper_controller_output_indexes.insert(output_index);
                                let output = tx
                                    .outputs
                                    .iter()
                                    .find(|out| out.index as i32 == output_index)
                                    .context("wrapper continuation output is missing")?;
                                let script_pubkey = hex::decode(&output.script_public_key)
                                    .context("decode wrapper continuation script public key")?;
                                anyhow::ensure!(
                                    p2sh_script_hash(&script_pubkey) == Some(blake2b_256(reveal)),
                                    "wrapper continuation output does not match revealed controller script"
                                );
                                ensure_wrapper_output_address(
                                    output
                                        .script_public_key_address
                                        .as_deref()
                                        .context("wrapper continuation address is missing")?,
                                    &blake2b_256(reveal),
                                )?;
                                anyhow::ensure!(
                                    classification.args.is_object(),
                                    "wrapper controller state could not be decoded"
                                );
                                kcc20_output_states.insert(
                                    output_index,
                                    (covenant_id.clone(), classification.args.clone()),
                                );
                                kcc20_touched.insert(covenant_id.clone());
                                merge_json_object(&mut decoded_args, action_args);
                            }
                            let canonical_override =
                                tn12_indexer_decoder::interpretation("wrapper_token_input", kcc20_wrapper::decode_wrap_token_input_index(&sig_script))?
                                    .and_then(|input_index| {
                                        spent_covenant_ids_by_input.get(&input_index).cloned()
                                    });
                            if let (Some(args), Some(canonical_token_id)) =
                                (decoded_args.as_mut(), canonical_override.as_ref())
                            {
                                if let Some(object) = args.as_object_mut() {
                                    object.insert(
                                        "canonicalTokenId".to_string(),
                                        Value::String(hex::encode(canonical_token_id)),
                                    );
                                }
                            }
                            if let Some(outputs) = tn12_indexer_decoder::interpretation("kcc20_wrapper::decode_wrap_output_state_values", kcc20_wrapper::decode_wrap_output_state_values(
                                    &sig_script,
                                    canonical_override.as_deref(),
                                    &covenant_id,
                                ))?
                            {
                                let inferred_changes = upsert_inferred_kcc20_outputs(
                                    &mut conn,
                                    tx,
                                    &accepting_hash,
                                    &covenant_id,
                                    &outputs,
                                )
                                .await
                                .context("upsert inferred KCC20Wrapper wrap output states")?;
                                persisted_change |= inferred_changes > 0;
                                for (output_index, state) in outputs {
                                    kcc20_output_states
                                        .insert(output_index, (covenant_id.clone(), state));
                                }
                                kcc20_touched.insert(covenant_id.clone());
                            }
                        }

                        if classification.template_name == "KCC20FeeTicket" {
                            if let Some(action_args) = tn12_indexer_decoder::interpretation("kcc20_fee_ticket::decode_action_args", kcc20_fee_ticket::decode_action_args(&sig_script))?
                            {
                                merge_json_object(&mut decoded_args, action_args);
                            }
                            let state = tn12_indexer_decoder::interpretation("kcc20_fee_ticket::decode_reveal_state_value", kcc20_fee_ticket::decode_reveal_state_value(reveal))?;
                             {
                                let result = sqlx::query(
                                    r#"UPDATE covenant_utxos
                                       SET state = COALESCE(state, $1)
                                       WHERE txid = $2 AND vout = $3
                                         AND state IS NULL"#,
                                )
                                .bind(&state)
                                .bind(&prev_txid)
                                .bind(prev_vout)
                                .execute(&mut **conn)
                                .await
                                .context("store KCC20FeeTicket spent input state")?;
                                persisted_change |= result.rows_affected() > 0;
                            }

                            if let Some(outputs) = tn12_indexer_decoder::interpretation("kcc20_fee_ticket::decode_output_state_values", kcc20_fee_ticket::decode_output_state_values(&sig_script, reveal))?
                            {
                                let inferred_changes = upsert_inferred_kcc20_outputs(
                                    &mut conn,
                                    tx,
                                    &accepting_hash,
                                    &covenant_id,
                                    &outputs,
                                )
                                .await
                                .context("upsert inferred KCC20FeeTicket output states")?;
                                persisted_change |= inferred_changes > 0;
                            }
                        }

                        if classification.template_name == "KCOMVesting" {
                            let state = tn12_indexer_decoder::interpretation("kcom_vesting::decode_reveal_state_value", kcom_vesting::decode_reveal_state_value(reveal))?;
                            sqlx::query("UPDATE covenant_utxos SET state = $1 WHERE txid = $2 AND vout = $3")
                                .bind(&state).bind(&prev_txid).bind(prev_vout).execute(&mut **conn).await?;
                            let outputs = kcom_vesting::decode_successors(
                                tx,
                                input_index,
                                &covenant_id,
                                &sig_script,
                                reveal,
                            )?;
                            let changes = upsert_inferred_kcc20_outputs(
                                &mut conn,
                                tx,
                                &accepting_hash,
                                &covenant_id,
                                &outputs,
                            )
                            .await?;
                            persisted_change |= changes > 0;
                        }

                        if classification.template_name == "KCOMInitialize" {
                            let (source_script, source_amount): (Vec<u8>, i64) = sqlx::query_as(
                                "SELECT script_pubkey, amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                            ).bind(&prev_txid).bind(prev_vout).bind(&covenant_id)
                                .fetch_one(&mut **conn).await
                                .context("authenticated initializer source is absent")?;
                            let (graph_id, outputs) = kcom_claim::decode_initialize_successors(
                                tx, input_index, &sig_script, reveal,
                                &source_script, u64::try_from(source_amount)?,
                            )?;
                            // The graph covenant row is created in the output
                            // pass below. Carry authenticated states into that
                            // pass instead of inserting UTXOs before their FK.
                            for (index, state) in outputs {
                                if state["modeName"] == "KCOMVault" {
                                    kcom_initializer_vault_output_indexes.insert(index);
                                }
                                kcc20_output_states.insert(index, (graph_id.clone(), state));
                            }
                        }

                        if classification.template_name == "KCOMFactory" {
                            let outputs = kcom_claim::decode_factory_successors(
                                tx,
                                input_index,
                                &covenant_id,
                                &sig_script,
                                reveal,
                            )?;
                            let changes = upsert_inferred_kcc20_outputs(
                                &mut conn,
                                tx,
                                &accepting_hash,
                                &covenant_id,
                                &outputs,
                            )
                            .await?;
                            persisted_change |= changes > 0;
                        }

                        if classification.template_name == "KCOMClaimShard" {
                            let outputs = kcom_claim::decode_shard_successors(
                                tx,
                                input_index,
                                &covenant_id,
                                &sig_script,
                                reveal,
                            )?;
                            let changes = upsert_inferred_kcc20_outputs(
                                &mut conn,
                                tx,
                                &accepting_hash,
                                &covenant_id,
                                &outputs,
                            )
                            .await?;
                            persisted_change |= changes > 0;
                            if classification.entrypoint.as_deref() == Some("select") {
                                let details = kcom_claim::decode_selection_action_details(
                                    &sig_script, reveal,
                                )?;
                                merge_json_object(&mut decoded_args, details);
                            }
                        }

                        if classification.template_name == "KCOMSettlement" {
                            let outputs = kcom_claim::decode_settlement_successors(
                                tx,
                                input_index,
                                &covenant_id,
                                &sig_script,
                                reveal,
                            )?;
                            let changes = upsert_inferred_kcc20_outputs(
                                &mut conn,
                                tx,
                                &accepting_hash,
                                &covenant_id,
                                &outputs,
                            )
                            .await?;
                            persisted_change |= changes > 0;
                            if classification.entrypoint.as_deref() == Some("collect") {
                                pending_kcom_settlement_collections.push((input_index, reveal.clone(), covenant_id.clone()));
                            } else if classification.entrypoint.as_deref() == Some("settle") {
                                pending_kcom_settlement_claims.push((input_index, reveal.clone(), covenant_id.clone()));
                            }
                        }

                        if classification.template_name == "KCOMVault"
                            && classification.entrypoint.as_deref() == Some("fund")
                        {
                            pending_kcom_vault_funds.push((input_index, reveal.clone(), covenant_id.clone()));
                        }
                        if classification.template_name == "KCOMVault"
                            && classification.entrypoint.as_deref() == Some("open")
                        {
                            pending_kcom_vault_opens.push((input_index, reveal.clone(), covenant_id.clone()));
                        }
                        if classification.template_name == "KCOMVault"
                            && classification.entrypoint.as_deref() == Some("seal")
                        {
                            pending_kcom_vault_seals.push((input_index, reveal.clone(), covenant_id.clone()));
                        }
                        if classification.template_name == "KCOMVault"
                            && matches!(classification.entrypoint.as_deref(), Some("activate_partial" | "activate_final"))
                        {
                            pending_kcom_activations.push((input_index, reveal.clone(), covenant_id.clone()));
                        }
                        if classification.template_name == "KCOMVault"
                            && matches!(classification.entrypoint.as_deref(), Some("recover_partial" | "recover_final"))
                        {
                            pending_kcom_recoveries.push((input_index, reveal.clone(), covenant_id.clone()));
                        }

                        if classification.template_name == "KCC20Vesting" {
                            let state = tn12_indexer_decoder::interpretation("kcc20_vesting::decode_reveal_state_value", kcc20_vesting::decode_reveal_state_value(reveal))?;
                             {
                                let result = sqlx::query(
                                    r#"UPDATE covenant_utxos
                                       SET state = COALESCE(state, $1)
                                       WHERE txid = $2 AND vout = $3
                                         AND state IS NULL"#,
                                )
                                .bind(&state)
                                .bind(&prev_txid)
                                .bind(prev_vout)
                                .execute(&mut **conn)
                                .await
                                .context("store KCC20Vesting spent input state")?;
                                persisted_change |= result.rows_affected() > 0;
                            }

                            if let Some(outputs) = tn12_indexer_decoder::interpretation("kcc20_vesting::decode_output_state_values", kcc20_vesting::decode_output_state_values(&sig_script, reveal))?
                            {
                                let inferred_changes = upsert_inferred_kcc20_outputs(
                                    &mut conn,
                                    tx,
                                    &accepting_hash,
                                    &covenant_id,
                                    &outputs,
                                )
                                .await
                                .context("upsert inferred KCC20Vesting output states")?;
                                persisted_change |= inferred_changes > 0;
                            }
                        }

                        if classification.template_name == "ApiPaymentChannel" {
                            let input_value_sompi = covenant_input_amount_sompi(
                                &mut conn, input, &prev_txid, prev_vout,
                            )
                            .await
                            .context("read ApiPaymentChannel input amount")?;
                            let channel_id = hex::encode(&covenant_id);
                            let open_txid = covenant_genesis_txid_hex(&mut conn, &covenant_id)
                                .await?
                                .unwrap_or_else(|| input.previous_outpoint_hash.clone());
                            upsert_indexed_api_payment_channel_open(
                                &mut **conn,
                                indexed_api_channel_open(
                                    &classification.args,
                                    &channel_id,
                                    &self.network_id,
                                    &open_txid,
                                    input_value_sompi,
                                    block_time,
                                )?,
                            )
                            .await
                            .context("upsert indexed ApiPaymentChannel open")?;

                            if let Some(action) =
                                tn12_indexer_decoder::interpretation("payment_channel_action", api_payment_channel::decode_action_projection(&sig_script))
                                    .context("decode ApiPaymentChannel spend args")?
                            {
                                match action {
                                    ApiPaymentChannelAction::Settle {
                                        total_spent_sompi,
                                        settlement_fee_sompi,
                                        ..
                                    } => {
                                        let payer_refund_sompi = input_value_sompi
                                            .checked_sub(total_spent_sompi)
                                            .and_then(|v| v.checked_sub(settlement_fee_sompi))
                                            .context(
                                                "ApiPaymentChannel settle values exceed input",
                                            )?;
                                        apply_indexed_api_payment_channel_settlement(
                                            &mut **conn,
                                            IndexedApiPaymentChannelSettlement {
                                                channel_id,
                                                txid_hex: tx.transaction_id.clone(),
                                                settled_total_sompi: total_spent_sompi,
                                                provider_amount_sompi: total_spent_sompi,
                                                payer_refund_sompi,
                                                indexed_at_ms: block_time,
                                            },
                                        )
                                        .await
                                        .context("apply indexed ApiPaymentChannel settlement")?;
                                    }
                                    ApiPaymentChannelAction::CooperativeClose {
                                        provider_amount_sompi,
                                        settlement_fee_sompi,
                                        ..
                                    } => {
                                        let payer_refund_sompi = input_value_sompi
                                            .checked_sub(provider_amount_sompi)
                                            .and_then(|v| v.checked_sub(settlement_fee_sompi))
                                            .context(
                                                "ApiPaymentChannel cooperative close values exceed input",
                                            )?;
                                        apply_indexed_api_payment_channel_settlement(
                                            &mut **conn,
                                            IndexedApiPaymentChannelSettlement {
                                                channel_id,
                                                txid_hex: tx.transaction_id.clone(),
                                                settled_total_sompi: provider_amount_sompi,
                                                provider_amount_sompi,
                                                payer_refund_sompi,
                                                indexed_at_ms: block_time,
                                            },
                                        )
                                        .await
                                        .context(
                                            "apply indexed ApiPaymentChannel cooperative close",
                                        )?;
                                    }
                                    ApiPaymentChannelAction::Refund { .. } => {
                                        apply_indexed_api_payment_channel_refund(
                                            &mut **conn,
                                            IndexedApiPaymentChannelRefund {
                                                channel_id,
                                                txid_hex: tx.transaction_id.clone(),
                                                indexed_at_ms: block_time,
                                            },
                                        )
                                        .await
                                        .context("apply indexed ApiPaymentChannel refund")?;
                                    }
                                    ApiPaymentChannelAction::ContinueChannel {
                                        channel_output_index,
                                        new_refund_after_ms,
                                        new_max_spend_sompi,
                                    } => {
                                        let continuation_output = tx
                                            .outputs
                                            .iter()
                                            .find(|out| out.index as i32 == channel_output_index)
                                            .with_context(|| {
                                                format!(
                                                    "ApiPaymentChannel continuation output {channel_output_index} missing"
                                                )
                                            })?;
                                        apply_indexed_api_payment_channel_continuation(
                                            &mut **conn,
                                            IndexedApiPaymentChannelContinuation {
                                                channel_id,
                                                txid_hex: tx.transaction_id.clone(),
                                                vout: channel_output_index,
                                                deposit_sompi: i64::try_from(
                                                    continuation_output.amount,
                                                )
                                                .context(
                                                    "ApiPaymentChannel continuation output amount overflows i64",
                                                )?,
                                                max_spend_sompi: new_max_spend_sompi,
                                                refund_after_ms: new_refund_after_ms,
                                                indexed_at_ms: block_time,
                                            },
                                        )
                                        .await
                                        .context(
                                            "apply indexed ApiPaymentChannel continuation",
                                        )?;
                                    }
                                    ApiPaymentChannelAction::RequestRefundClose {
                                        channel_output_index,
                                        final_refund_after_ms,
                                        ..
                                    } => {
                                        let close_output = tx
                                            .outputs
                                            .iter()
                                            .find(|out| out.index as i32 == channel_output_index)
                                            .with_context(|| {
                                                format!(
                                                    "ApiPaymentChannel close output {channel_output_index} missing"
                                                )
                                            })?;
                                        apply_indexed_api_payment_channel_close_requested(
                                            &mut **conn,
                                            IndexedApiPaymentChannelCloseRequested {
                                                channel_id,
                                                txid_hex: tx.transaction_id.clone(),
                                                vout: channel_output_index,
                                                deposit_sompi: i64::try_from(close_output.amount)
                                                    .context(
                                                        "ApiPaymentChannel close output amount overflows i64",
                                                    )?,
                                                close_after_ms: final_refund_after_ms,
                                                indexed_at_ms: block_time,
                                            },
                                        )
                                        .await
                                        .context(
                                            "apply indexed ApiPaymentChannel close requested",
                                        )?;
                                    }
                                }
                            }
                        }

                        if classification.kind == "covenant" && classification_backfilled {
                            // If the wallet wrote a claim at deploy time,
                            // cross-check it against the on-chain truth and
                            // flip claim_verified iff template name + arg
                            // identities line up. Mismatch leaves the claim
                            // visible but unverified — see the soft-mismatch
                            // policy in feat/claimed-constructor-params.
                            let claim_row: Option<(Option<String>, Option<Value>, bool)> =
                                sqlx::query_as(
                                    r#"SELECT claimed_template, claimed_args, claim_verified
                                   FROM covenants WHERE covenant_id = $1"#,
                                )
                                .bind(&covenant_id)
                                .fetch_optional(&mut **conn)
                                .await
                                .context("read claim for verification")?;
                            if let Some((Some(claim_tmpl), Some(claim_blob), already_verified)) =
                                claim_row
                            {
                                if !already_verified && claim_tmpl == classification.template_name {
                                    let claimed: Option<claim::ClaimedDeployment> =
                                        serde_json::from_value(claim_blob.clone()).ok().or_else(
                                            || {
                                                // Tolerate claims stored as the legacy `{"tmpl":...,"args":[...]}` blob
                                                // by reconstructing the typed form when the column shape predates v2.
                                                let tmpl =
                                                    claim_blob.get("tmpl")?.as_str()?.to_string();
                                                let args =
                                                    claim_blob.get("args")?.as_array()?.clone();
                                                Some(claim::ClaimedDeployment {
                                                    v: 1,
                                                    tmpl,
                                                    args: args
                                                        .into_iter()
                                                        .filter_map(|v| {
                                                            serde_json::from_value(v).ok()
                                                        })
                                                        .collect(),
                                                    meta: None,
                                                })
                                            },
                                        );
                                    let effective_args =
                                        decoded_args.as_ref().unwrap_or(&classification.args);
                                    let matches = claimed
                                        .as_ref()
                                        .map(|c| {
                                            claim_matches_decoded_for_template(
                                                c,
                                                &classification.template_name,
                                                effective_args,
                                            )
                                        })
                                        .unwrap_or(false);
                                    if matches {
                                        sqlx::query(
                                            r#"UPDATE covenants
                                               SET claim_verified = TRUE, claim_verified_at_ms = $1
                                               WHERE covenant_id = $2 AND claim_verified = FALSE"#,
                                        )
                                        .bind(block_time)
                                        .bind(&covenant_id)
                                        .execute(&mut **conn)
                                        .await
                                        .context("mark claim_verified")?;
                                    }
                                }
                            }
                        }
                    } else {
                        let result = sqlx::query(
                            r#"UPDATE covenants
                               SET classification_kind = 'unknown',
                                   classification_status = 'unmatched'
                               WHERE covenant_id = $1
                                 AND classification_status <> 'matched'
                                 AND (
                                     classification_kind IS DISTINCT FROM 'unknown'
                                     OR classification_status IS DISTINCT FROM 'unmatched'
                                 )"#,
                        )
                        .bind(&covenant_id)
                        .execute(&mut **conn)
                        .await
                        .context("mark unmatched classification")?;
                        persisted_change |= result.rows_affected() > 0;
                    }
                } else {
                    let result = sqlx::query(
                        r#"UPDATE covenants
                           SET classification_kind = 'unknown',
                               classification_status = 'unmatched'
                           WHERE covenant_id = $1
                             AND classification_status <> 'matched'
                             AND (
                                 classification_kind IS DISTINCT FROM 'unknown'
                                 OR classification_status IS DISTINCT FROM 'unmatched'
                             )"#,
                    )
                    .bind(&covenant_id)
                    .execute(&mut **conn)
                    .await
                    .context("mark missing-reveal classification")?;
                    persisted_change |= result.rows_affected() > 0;
                }

                let res = sqlx::query(
                    r#"INSERT INTO covenant_actions
                       (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
                       VALUES ($1, $2, $3, $4, 'spend', $5, $6, NULL, $7)
                       ON CONFLICT DO NOTHING"#,
                )
                .bind(&covenant_id)
                .bind(&spent_by_txid)
                .bind(&accepting_hash)
                .bind(block_time)
                .bind(&entrypoint)
                .bind(&inputs_json)
                .bind(&decoded_args)
                .execute(&mut **conn)
                .await
                .context("insert spend action")?;
                let actions_inserted = res.rows_affected();
                stats.actions_inserted += actions_inserted;
                persisted_change |= actions_inserted > 0;
                if is_kcom_action || replay_deferred {
                    // A pre-decoder ingest already has this spend row with empty
                    // action details. Repair it under the same writer lock as
                    // the authenticated successor reconstruction. Match the
                    // exact outpoint because two graph actors may spend in one tx.
                    // The address is a derived display label; older rows used the
                    // family address. Only a missing, authenticated fast-profile
                    // annotation may be added to otherwise identical constructor
                    // args. Explicit profiles and all contract fields stay strict.
                    let updated = sqlx::query(
                        r#"UPDATE covenant_actions
                           SET entrypoint=$1, decoded_args=$2, inputs=$6
                           WHERE covenant_id=$3 AND txid=$4 AND block_hash=$5
                             AND action='spend'
                             AND inputs - 'address' = $6::jsonb - 'address'
                             AND (entrypoint IS NULL OR entrypoint=$1)
                             AND (decoded_args IS NULL OR decoded_args=$2 OR (
                               NOT (decoded_args ? 'artifactProfile')
                               AND NOT (decoded_args ? 'testOnly')
                               AND $2::jsonb->>'artifactProfile'='kcom-fast-tn10-60s-v1'
                               AND $2::jsonb->'testOnly'='true'::jsonb
                               AND decoded_args=$2::jsonb-'artifactProfile'-'testOnly'
                             ))"#,
                    )
                    .bind(&entrypoint)
                    .bind(&decoded_args)
                    .bind(&covenant_id)
                    .bind(&spent_by_txid)
                    .bind(&accepting_hash)
                    .bind(&inputs_json)
                    .execute(&mut **conn)
                    .await
                    .context("repair authenticated KCOM spend action")?;
                    anyhow::ensure!(updated.rows_affected() == 1,
                        "KCOM spend action conflicts with accepted replay");
                }
            }
        }

        for (input_index, signature_script, reveal_script, covenant_id) in
            pending_kcc20_orderbook_merges
        {
            let (output_index, state) = decode_kcc20_orderbook_merge_output(
                tx,
                input_index,
                &signature_script,
                &reveal_script,
                &covenant_id,
                &spent_covenant_ids_by_input,
            )
            .with_context(|| {
                format!(
                    "project KCC20Orderbook merge for tx {} input {}",
                    tx.transaction_id, input_index
                )
            })?
            .context("KCC20Orderbook primary merge did not produce output state")?;
            kcc20_output_states.insert(output_index, (covenant_id.clone(), state));
            kcc20_touched.insert(covenant_id);
        }

        for (vault_input_index, vault_reveal, graph_id) in pending_kcom_vault_funds {
            let vault_state = kcom_claim::KcomClaimDecoder::new(KnownTemplate::KcomVault)
                .decode_constructor(&vault_reveal)?;
            let token_id = hex::decode(vault_state["token_id"].as_str()
                .context("funding token ID")?)?;
            let token_peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != vault_input_index && **id == token_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(token_peers.len() == 1, "funding needs one canonical token input");
            let token_input_index = token_peers[0];
            let token_signature = hex::decode(&tx.inputs[token_input_index].signature_script)
                .context("decode funding token witness")?;
            let token_reveal = extract_last_push(&token_signature)
                .context("funding token reveal is missing")?;
            let mut funding_tx = tx.clone();
            for (index, id) in [(vault_input_index, &graph_id), (token_input_index, &token_id)] {
                let input = &tx.inputs[index];
                let txid = hex::decode(&input.previous_outpoint_hash)?;
                let vout = input.previous_outpoint_index.parse::<i32>()?;
                let (amount, script): (i64, Vec<u8>) = sqlx::query_as(
                    "SELECT amount_sompi, script_pubkey FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                ).bind(&txid).bind(vout).bind(id).fetch_one(&mut **conn).await
                    .context("read authenticated funding source")?;
                let amount = u64::try_from(amount).context("invalid funding source KAS")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "funding REST amount differs from indexed UTXO");
                if let Some(reported) = &input.previous_outpoint_script {
                    let reported = hex::decode(reported.strip_prefix("0000").unwrap_or(reported))?;
                    anyhow::ensure!(reported == script, "funding REST script differs from indexed UTXO");
                }
                funding_tx.inputs[index].previous_outpoint_amount = Some(amount);
                funding_tx.inputs[index].previous_outpoint_script = Some(hex::encode(script));
            }
            let (vault_output, token_output) = kcom_claim::decode_vault_fund_successors(
                &funding_tx, vault_input_index, token_input_index, &graph_id, &token_id,
                &vault_reveal, &token_reveal,
            )?;
            let graph_changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &graph_id, &[vault_output],
            ).await?;
            let token_changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &token_id, &[token_output],
            ).await?;
            persisted_change |= graph_changes + token_changes > 0;
        }

        for (vault_input_index, vault_reveal, covenant_id) in pending_kcom_vault_opens {
            let peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != vault_input_index && **id == covenant_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(peers.len() == 1, "vault open needs one same-lineage factory");
            let factory_input_index = peers[0];
            let factory_signature = hex::decode(&tx.inputs[factory_input_index].signature_script)
                .context("decode opening factory witness")?;
            let factory_reveal = extract_last_push(&factory_signature)
                .context("opening factory reveal is missing")?;
            let mut open_tx = tx.clone();
            for index in [factory_input_index, vault_input_index] {
                let input = &tx.inputs[index];
                let source_txid = hex::decode(&input.previous_outpoint_hash)?;
                let source_vout = input.previous_outpoint_index.parse::<i32>()?;
                let (amount, script): (i64, Vec<u8>) = sqlx::query_as(
                    "SELECT amount_sompi, script_pubkey FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                )
                .bind(&source_txid).bind(source_vout).bind(&covenant_id)
                .fetch_one(&mut **conn).await
                .context("read authenticated opening source")?;
                let amount = u64::try_from(amount).context("invalid opening source amount")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "opening REST source amount differs from indexed UTXO");
                if let Some(reported) = input.previous_outpoint_script.as_deref() {
                    let reported = reported.strip_prefix("0000").unwrap_or(reported);
                    anyhow::ensure!(hex::decode(reported)? == script,
                        "opening REST source script differs from indexed UTXO");
                }
                open_tx.inputs[index].previous_outpoint_amount = Some(amount);
                open_tx.inputs[index].previous_outpoint_script = Some(hex::encode(script));
            }
            let output = kcom_claim::decode_vault_open_successor(
                &open_tx, factory_input_index, vault_input_index, &covenant_id,
                &factory_reveal, &vault_reveal,
            )?;
            let changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &covenant_id, &[output],
            ).await?;
            persisted_change |= changes > 0;
        }

        for (vault_input_index, vault_reveal, covenant_id) in pending_kcom_vault_seals {
            let peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != vault_input_index && **id == covenant_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(peers.len() == 1, "vault seal needs one same-lineage collector");
            let collector_input_index = peers[0];
            let collector_signature = hex::decode(&tx.inputs[collector_input_index].signature_script)
                .context("decode vault-seal collector witness")?;
            let collector_reveal = extract_last_push(&collector_signature)
                .context("vault-seal collector reveal is missing")?;
            let mut seal_tx = tx.clone();
            for index in [vault_input_index, collector_input_index] {
                let input = &tx.inputs[index];
                let source_txid = hex::decode(&input.previous_outpoint_hash)?;
                let source_vout = input.previous_outpoint_index.parse::<i32>()?;
                let amount: i64 = sqlx::query_scalar(
                    "SELECT amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                )
                .bind(&source_txid).bind(source_vout).bind(&covenant_id)
                .fetch_one(&mut **conn).await
                .context("read authenticated vault-seal source amount")?;
                let amount = u64::try_from(amount).context("invalid vault-seal source amount")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "vault-seal REST source amount differs from indexed UTXO");
                seal_tx.inputs[index].previous_outpoint_amount = Some(amount);
            }
            let output = kcom_claim::decode_vault_seal_successor(
                &seal_tx, vault_input_index, collector_input_index, &covenant_id,
                &vault_reveal, &collector_reveal,
            )?;
            let changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &covenant_id, &[output],
            ).await?;
            persisted_change |= changes > 0;
        }

        for (collector_input_index, collector_reveal, covenant_id) in pending_kcom_settlement_collections {
            let peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != collector_input_index && **id == covenant_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(peers.len() == 1, "collection needs one same-lineage shard");
            let shard_input_index = peers[0];
            let shard_signature = hex::decode(&tx.inputs[shard_input_index].signature_script)
                .context("decode collected shard witness")?;
            let shard_reveal = extract_last_push(&shard_signature)
                .context("collected shard reveal is missing")?;
            let mut collection_tx = tx.clone();
            for index in [collector_input_index, shard_input_index] {
                let input = &tx.inputs[index];
                let source_txid = hex::decode(&input.previous_outpoint_hash)?;
                let source_vout = input.previous_outpoint_index.parse::<i32>()?;
                let amount: i64 = sqlx::query_scalar(
                    "SELECT amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                )
                .bind(&source_txid).bind(source_vout).bind(&covenant_id)
                .fetch_one(&mut **conn).await
                .context("read authenticated collection source amount")?;
                let amount = u64::try_from(amount).context("invalid collection source amount")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "collection REST source amount differs from indexed UTXO");
                collection_tx.inputs[index].previous_outpoint_amount = Some(amount);
            }
            let output = kcom_claim::decode_settlement_collect_successor(
                &collection_tx, collector_input_index, shard_input_index, &covenant_id,
                &collector_reveal, &shard_reveal,
            )?;
            let changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &covenant_id, &[output],
            ).await?;
            persisted_change |= changes > 0;
        }

        for (collector_input_index, collector_reveal, covenant_id) in pending_kcom_settlement_claims {
            let peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != collector_input_index && **id == covenant_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(peers.len() == 1, "settlement needs one same-lineage commitment");
            let commitment_input_index = peers[0];
            let commitment_signature = hex::decode(&tx.inputs[commitment_input_index].signature_script)
                .context("decode settled commitment witness")?;
            let commitment_reveal = extract_last_push(&commitment_signature)
                .context("settled commitment reveal is missing")?;
            let mut settlement_tx = tx.clone();
            for index in [collector_input_index, commitment_input_index] {
                let input = &tx.inputs[index];
                let source_txid = hex::decode(&input.previous_outpoint_hash)?;
                let source_vout = input.previous_outpoint_index.parse::<i32>()?;
                let amount: i64 = sqlx::query_scalar(
                    "SELECT amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                )
                .bind(&source_txid).bind(source_vout).bind(&covenant_id)
                .fetch_one(&mut **conn).await
                .context("read authenticated settlement source amount")?;
                let amount = u64::try_from(amount).context("invalid settlement source amount")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "settlement REST source amount differs from indexed UTXO");
                settlement_tx.inputs[index].previous_outpoint_amount = Some(amount);
            }
            let outputs = kcom_claim::decode_settlement_claim_successors(
                &settlement_tx, collector_input_index, commitment_input_index, &covenant_id,
                &collector_reveal, &commitment_reveal,
            )?;
            let changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &covenant_id, &outputs,
            ).await?;
            persisted_change |= changes > 0;
        }

        for (vault_input_index, vault_reveal, graph_id) in pending_kcom_activations {
            let graph_peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != vault_input_index && **id == graph_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(graph_peers.len() == 1, "activation needs one same-lineage entitlement");
            let entitlement_input_index = graph_peers[0];
            let vault_state = kcom_claim::KcomClaimDecoder::new(KnownTemplate::KcomVault)
                .decode_constructor(&vault_reveal)?;
            let token_id = hex::decode(vault_state["token_id"].as_str().context("activation token ID")?)?;
            let token_peers = spent_covenant_ids_by_input.iter()
                .filter(|(_, id)| **id == token_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(token_peers.len() == 1, "activation needs one canonical token input");
            let token_input_index = token_peers[0];
            let mut activation_tx = tx.clone();
            let mut reveals = Vec::new();
            for (index, id) in [(vault_input_index, &graph_id), (entitlement_input_index, &graph_id), (token_input_index, &token_id)] {
                let input = &tx.inputs[index];
                let signature = hex::decode(&input.signature_script)?;
                let reveal = extract_last_push(&signature).context("activation reveal is missing")?;
                reveals.push(reveal);
                let txid = hex::decode(&input.previous_outpoint_hash)?;
                let vout = input.previous_outpoint_index.parse::<i32>()?;
                let (amount, script): (i64, Vec<u8>) = sqlx::query_as(
                    "SELECT amount_sompi, script_pubkey FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                ).bind(&txid).bind(vout).bind(id).fetch_one(&mut **conn).await
                    .context("read authenticated activation source")?;
                let amount = u64::try_from(amount).context("invalid activation source KAS")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "activation REST amount differs from indexed UTXO");
                if let Some(reported) = &input.previous_outpoint_script {
                    let reported = hex::decode(reported.strip_prefix("0000").unwrap_or(reported))?;
                    anyhow::ensure!(reported == script, "activation REST script differs from indexed UTXO");
                }
                activation_tx.inputs[index].previous_outpoint_amount = Some(amount);
                activation_tx.inputs[index].previous_outpoint_script = Some(hex::encode(script));
            }
            let (vault_outputs, position_id, position_output) = kcom_claim::decode_activation_successors(
                &activation_tx, vault_input_index, entitlement_input_index, token_input_index,
                &graph_id, &token_id, &reveals[0], &reveals[1], &reveals[2],
            )?;
            let graph_changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &graph_id, &vault_outputs,
            ).await?;
            // The genesis position covenant row is inserted by the normal output pass below.
            // Carry its authenticated state into that pass so its first spend is unnecessary.
            authenticated_kcom_positions.push((position_id.clone(), position_output.1.clone()));
            kcc20_output_states.insert(position_output.0, (position_id, position_output.1));
            persisted_change |= graph_changes > 0;
        }

        for (vault_input_index, vault_reveal, graph_id) in pending_kcom_recoveries {
            let vault_state = kcom_claim::KcomClaimDecoder::new(KnownTemplate::KcomVault)
                .decode_constructor(&vault_reveal)?;
            let token_id = hex::decode(vault_state["token_id"].as_str()
                .context("recovery token ID")?)?;
            let token_peers = spent_covenant_ids_by_input.iter()
                .filter(|(index, id)| **index != vault_input_index && **id == token_id)
                .map(|(index, _)| *index).collect::<Vec<_>>();
            anyhow::ensure!(token_peers.len() == 1,
                "recovery needs one canonical token input");
            let token_input_index = token_peers[0];
            let token_signature = hex::decode(&tx.inputs[token_input_index].signature_script)
                .context("decode recovery token witness")?;
            let token_reveal = extract_last_push(&token_signature)
                .context("recovery token reveal is missing")?;
            let mut recovery_tx = tx.clone();
            for (index, id) in [(vault_input_index, &graph_id), (token_input_index, &token_id)] {
                let input = &tx.inputs[index];
                let txid = hex::decode(&input.previous_outpoint_hash)?;
                let vout = input.previous_outpoint_index.parse::<i32>()?;
                let (amount, script): (i64, Vec<u8>) = sqlx::query_as(
                    "SELECT amount_sompi, script_pubkey FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
                ).bind(&txid).bind(vout).bind(id).fetch_one(&mut **conn).await
                    .context("read authenticated recovery source")?;
                let amount = u64::try_from(amount).context("invalid recovery source KAS")?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "recovery REST amount differs from indexed UTXO");
                if let Some(reported) = &input.previous_outpoint_script {
                    let reported = hex::decode(reported.strip_prefix("0000").unwrap_or(reported))?;
                    anyhow::ensure!(reported == script,
                        "recovery REST script differs from indexed UTXO");
                }
                recovery_tx.inputs[index].previous_outpoint_amount = Some(amount);
                recovery_tx.inputs[index].previous_outpoint_script = Some(hex::encode(script));
            }
            let (output, token_outputs) = kcom_claim::decode_recovery_successor(
                &recovery_tx, vault_input_index, token_input_index,
                &graph_id, &token_id, &vault_reveal, &token_reveal,
            )?;
            let vault_changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &graph_id, &[output],
            ).await?;
            let token_changes = upsert_inferred_kcc20_outputs(
                &mut conn, tx, &accepting_hash, &token_id, &token_outputs,
            ).await?;
            persisted_change |= vault_changes > 0 || token_changes > 0;
        }

        for (signature_script, entrypoint, leader_state, market_id) in pending_kcc20_fee_groups {
            let mut input_indices = spent_covenant_ids_by_input
                .iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index))
                .collect::<Vec<_>>();
            input_indices.sort_unstable();
            if let Some((output_index, state)) = kcc20_fee_v1::grouped_receipt_output_state(
                tx, &signature_script, &entrypoint, &leader_state, &market_id, &input_indices,
            )
            .with_context(|| format!("project fee receipt for tx {}", tx.transaction_id))?
            {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee receipt projection overlaps another output"
                );
                kcc20_touched.insert(market_id);
            }
        }
        for (input_index, signature_script, current, market_id, argent) in pending_kcc20_fee_market_bindings {
            let outputs = kcc20_fee_v1::fee_market_binding_outputs(
                tx, input_index, &signature_script, &current, &market_id, argent,
            )
            .with_context(|| format!("project fee market binding for tx {}", tx.transaction_id))?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee market binding projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id, argent) in pending_kcc20_fee_market_wraps {
            let outputs = kcc20_fee_v1::fee_market_wrap_outputs(
                tx, input_index, &signature_script, &current, &market_id, argent,
            )
            .with_context(|| format!("project fee market wrap for tx {}", tx.transaction_id))?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee market wrap projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, market_id) in pending_kcc20_fee_market_merges {
            let mut market_inputs = spent_covenant_ids_by_input
                .iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index))
                .collect::<Vec<_>>();
            market_inputs.sort_unstable();
            anyhow::ensure!(
                market_inputs.first() == Some(&input_index),
                "fee holder merge leader must be first market input"
            );
            let states = market_inputs
                .iter()
                .map(|index| {
                    fee_market_holder_states_by_input.get(index).cloned()
                        .with_context(|| format!("missing fee holder merge state at input {index}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let (output_index, state) = kcc20_fee_v1::fee_market_merge_holders_output(
                tx, &market_inputs, &states, &market_id,
            )
            .with_context(|| format!("project fee holder merge for tx {}", tx.transaction_id))?;
            anyhow::ensure!(
                kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                "fee holder merge projection overlaps another output"
            );
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, holder_state, market_id) in pending_kcc20_fee_market_unwraps {
            let wrapper_inputs = spent_covenant_ids_by_input.iter()
                .filter_map(|(index, id)| {
                    (id == &market_id && fee_market_wrapper_states_by_input.contains_key(index))
                        .then_some(*index)
                }).collect::<Vec<_>>();
            anyhow::ensure!(wrapper_inputs.len() == 1, "fee market unwrap needs one wrapper input");
            let wrapper_input = wrapper_inputs[0];
            let (wrapper_state, argent) = fee_market_wrapper_states_by_input
                .get(&wrapper_input).context("missing fee unwrap wrapper state")?;
            let outputs = kcc20_fee_v1::fee_market_unwrap_outputs(
                tx, input_index, &signature_script, &holder_state, wrapper_input,
                wrapper_state, &market_id, *argent,
            )
            .with_context(|| format!("project fee market unwrap for tx {}", tx.transaction_id))?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee market unwrap projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id) in pending_kcc20_fee_market_asks {
            let outputs = kcc20_fee_v1::fee_market_create_ask_outputs(
                tx,
                input_index,
                &signature_script,
                &current,
                &market_id,
            )
            .with_context(|| {
                format!("project fee market createAsk for tx {}", tx.transaction_id)
            })?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states
                        .insert(output_index, (market_id.clone(), state))
                        .is_none(),
                    "fee market createAsk projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id) in pending_kcc20_fee_market_ask_cancels {
            let (output_index, state) = kcc20_fee_v1::fee_market_cancel_ask_output(
                tx, input_index, &signature_script, &current, &market_id,
            )
            .with_context(|| format!("project fee market cancelAsk for tx {}", tx.transaction_id))?;
            anyhow::ensure!(
                kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                "fee market cancelAsk projection overlaps another output"
            );
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id) in pending_kcc20_fee_market_bids {
            let outputs = kcc20_fee_v1::fee_market_create_bid_outputs(
                tx, input_index, &signature_script, &current, &market_id,
            )
            .with_context(|| format!("project fee market createBid for tx {}", tx.transaction_id))?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee market createBid projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id) in pending_kcc20_fee_market_buys {
            let mut market_inputs = spent_covenant_ids_by_input
                .iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index))
                .collect::<Vec<_>>();
            market_inputs.sort_unstable();
            let ask_sources = market_inputs
                .iter()
                .map(|index| {
                    fee_market_ask_states_by_input
                        .get(index)
                        .cloned()
                        .map(|state| (*index, state))
                        .with_context(|| {
                            format!("buyAsks input {index} has no authenticated ask state")
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(
                ask_sources
                    .first()
                    .is_some_and(|(index, state)| *index == input_index && state == &current),
                "buyAsks leader is not the first authenticated ask"
            );
            let outputs = kcc20_fee_v1::fee_market_buy_asks_outputs(
                tx,
                input_index,
                &signature_script,
                &ask_sources,
                &market_id,
            )
            .with_context(|| format!("project fee market buyAsks for tx {}", tx.transaction_id))?;
            persisted_change |= fee_trades::annotate(&mut conn, tx, &accepting_hash, &market_id, input_index,
                fee_trades::records("buyAsks", None, &ask_sources, &outputs)?).await?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states
                        .insert(output_index, (market_id.clone(), state))
                        .is_none(),
                    "fee market buyAsks projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, market_id) in pending_kcc20_fee_market_crosses {
            let mut indices = spent_covenant_ids_by_input.iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index)).collect::<Vec<_>>();
            indices.sort_unstable();
            anyhow::ensure!(indices.len() == 2 && indices[0] == input_index,
                "cross leader or complete market input set mismatch");
            let ask = fee_market_ask_states_by_input.get(&indices[0]).context("cross missing authenticated ask")?;
            let bid = fee_market_bid_states_by_input.get(&indices[1]).context("cross missing authenticated bid")?;
            let sources = vec![(indices[0], ask.clone()), (indices[1], bid.clone())];
            let mut cross_tx = tx.clone();
            for index in &indices {
                let input = &tx.inputs[*index];
                let amount: i64 = sqlx::query_scalar(
                    "SELECT amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3")
                    .bind(hex::decode(&input.previous_outpoint_hash)?)
                    .bind(input.previous_outpoint_index.parse::<i32>()?).bind(&market_id)
                    .fetch_one(&mut **conn).await.context("read authenticated cross principal")?;
                let amount = u64::try_from(amount)?;
                anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                    "cross REST amount differs from indexed UTXO");
                cross_tx.inputs[*index].previous_outpoint_amount = Some(amount);
            }
            let outputs = kcc20_fee_v1::fee_market_cross_outputs(&cross_tx, &signature_script, &sources, &market_id)
                .with_context(|| format!("project fee market cross for tx {}", tx.transaction_id))?;
            persisted_change |= fee_trades::annotate(&mut conn, tx, &accepting_hash, &market_id, input_index,
                fee_trades::records("crossWithBid", None, &sources, &outputs)?).await?;
            for (output_index, state) in outputs {
                anyhow::ensure!(kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee cross projection overlaps another output");
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, current, market_id) in pending_kcc20_fee_market_sells {
            let mut market_inputs = spent_covenant_ids_by_input.iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index))
                .collect::<Vec<_>>();
            market_inputs.sort_unstable();
            anyhow::ensure!(market_inputs.first() == Some(&input_index),
                "sellIntoBids leader is not the first market input");
            let bid_sources = market_inputs.iter().skip(1)
                .map(|index| fee_market_bid_states_by_input.get(index).cloned()
                    .map(|state| (*index, state))
                    .with_context(|| format!("sellIntoBids input {index} has no authenticated bid state")))
                .collect::<Result<Vec<_>>>()?;
            let outputs = kcc20_fee_v1::fee_market_sell_into_bids_outputs(
                tx, input_index, &signature_script, &current, &bid_sources, &market_id,
            )
            .with_context(|| format!("project fee market sellIntoBids for tx {}", tx.transaction_id))?;
            persisted_change |= fee_trades::annotate(&mut conn, tx, &accepting_hash, &market_id, input_index,
                fee_trades::records("sellIntoBids", Some(&current), &bid_sources, &outputs)?).await?;
            for (output_index, state) in outputs {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee market sellIntoBids projection overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }
        for (input_index, signature_script, entrypoint, current, account_id) in pending_kcc20_fee_accounts {
            if let Some((output_index, state)) = kcc20_fee_v1::fee_account_output_state(
                tx, input_index, &signature_script, &entrypoint, &current,
            )
            .with_context(|| format!("project fee account for tx {}", tx.transaction_id))?
            {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (account_id.clone(), state)).is_none(),
                    "fee account projection overlaps another output"
                );
                kcc20_touched.insert(account_id);
            }
        }
        for (input_index, signature_script, current, recipient_id) in pending_kcc20_fee_recipients {
            let input = &tx.inputs[input_index];
            let amount: i64 = sqlx::query_scalar(
                "SELECT amount_sompi FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3")
                .bind(hex::decode(&input.previous_outpoint_hash)?)
                .bind(input.previous_outpoint_index.parse::<i32>()?).bind(&recipient_id)
                .fetch_one(&mut **conn).await.context("read authenticated recipient principal")?;
            let amount = u64::try_from(amount)?;
            anyhow::ensure!(input.previous_outpoint_amount.is_none_or(|reported| reported == amount),
                "recipient REST amount differs from indexed UTXO");
            let mut hydrated = tx.clone();
            hydrated.inputs[input_index].previous_outpoint_amount = Some(amount);
            let (output_index, state) = kcc20_fee_v1::fee_recipient_output_state(
                &hydrated,input_index,&signature_script,&current,&recipient_id)
                .with_context(|| format!("project fee recipient for tx {}",tx.transaction_id))?;
            anyhow::ensure!(kcc20_output_states.insert(output_index,(recipient_id.clone(),state)).is_none(),
                "fee recipient projection overlaps another output");
            kcc20_touched.insert(recipient_id);
        }
        for (leader_index, signature_script, market_id) in pending_kcc20_fee_claims {
            let mut indices = spent_covenant_ids_by_input
                .iter()
                .filter_map(|(index, id)| (id == &market_id).then_some(*index))
                .collect::<Vec<_>>();
            indices.sort_unstable();
            if indices.first().copied() != Some(leader_index) { continue; }
            let receipts = indices.iter().map(|index| {
                fee_receipt_states_by_input.get(index).cloned()
                    .map(|state| (*index, state))
                    .with_context(|| format!("fee claim input {} has no authenticated receipt state", index))
            }).collect::<Result<Vec<_>>>()?;
            let projection = kcc20_fee_v1::fee_claim_output_state(
                tx, &signature_script, &market_id, &receipts,
            )
            .with_context(|| format!("project fee claim for tx {}", tx.transaction_id))?;
            let (account_id, account_state) = kcc20_output_states
                .get(&projection.account_output_index)
                .context("fee claim account successor was not projected")?;
            anyhow::ensure!(
                account_id.as_slice() == hex::decode(&projection.expected_account_id)?.as_slice()
                    && account_state["roleName"] == "account"
                    && account_state["token"] == projection.token_id
                    && account_state["market"] == hex::encode(&market_id)
                    && account_state["policy"] == projection.policy_id
                    && account_state["action_hash"] == projection.account_commitment,
                "fee claim account approval does not bind the selected receipts"
            );
            if let Some((output_index, state)) = projection.remainder {
                anyhow::ensure!(
                    kcc20_output_states.insert(output_index, (market_id.clone(), state)).is_none(),
                    "fee claim remainder overlaps another output"
                );
            }
            kcc20_touched.insert(market_id);
        }

        let txid_bytes = hex::decode(&tx.transaction_id)
            .with_context(|| format!("decoding txid {}", tx.transaction_id))?;

        // Parse the tx-level deployment envelope once (if any). Applies only
        // to *genesis* covenant outputs — continuations don't get a fresh
        // claim. None for txs without a tn12 payload, which is the common
        // case from non-opt-in wallets.
        let api_payment_channel_open_args_from_payload: Option<Value> = tx
            .payload
            .as_deref()
            .filter(|_| !opaque).and_then(parse_api_payment_channel_open_payload);
        if let Some(claim) = claim_from_payload.as_ref() {
            if claim.tmpl == "KCC20SnapshotController" {
                let blob = claim::claimed_args_jsonb(claim);
                if let Some(state) = snapshot_state_from_claimed_args(&blob) {
                    let p2sh_outputs = tx
                        .outputs
                        .iter()
                        .filter(|output| {
                            hex::decode(&output.script_public_key)
                                .ok()
                                .is_some_and(|spk| is_p2sh_script_pubkey(&spk))
                        })
                        .collect::<Vec<_>>();
                    if p2sh_outputs.len() == 1 {
                        let output = p2sh_outputs[0];
                        let output_indexes = [output.index];
                        let covenant_id = output
                            .canonical_covenant_id()
                            .and_then(|id| hex::decode(id).ok())
                            .filter(|id| id.len() == 32)
                            .or_else(|| {
                                compute_genesis_covenant_id_for_outputs(tx, &output_indexes)
                                    .and_then(|id| hex::decode(id).ok())
                                    .filter(|id| id.len() == 32)
                            });
                        if let Some(covenant_id) = covenant_id {
                            snapshot_output_states
                                .insert(output.index as i32, (covenant_id, state));
                        }
                    }
                }
            }
            if claim.tmpl == "KCC20" || claim.tmpl == "KCC20FeeTicket" {
                match claimed_genesis_states(tx, claim) {
                    Ok(Some((covenant_id, states))) => {
                        if tx.is_accepted && claim.tmpl == "KCC20FeeTicket" {
                            // Complete genesis proof matched the pinned script to the
                            // accepted output and authenticated its covenant binding.
                            verified_fee_ticket_genesis = states.first()
                                .map(|(_, state)| (covenant_id.clone(), state.clone()));
                        }
                        for (output_index, state) in states {
                            kcc20_output_states
                                .insert(output_index, (covenant_id.clone(), state));
                        }
                        kcc20_touched.insert(covenant_id);
                        refresh_kcc20_markets = true;
                    }
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        txid = %tx.transaction_id,
                        template = %claim.tmpl,
                        %error,
                        "deploy claim did not open every accepted output"
                    ),
                }
            }
            if claim.tmpl == "KCC20Wrapper" && !wrapper_reveal_is_action {
                let blob = claim::claimed_args_jsonb(claim);
                let mut p2sh_outputs = tx
                    .outputs
                    .iter()
                    .filter(|out| {
                        hex::decode(&out.script_public_key)
                            .map(|spk| is_p2sh_script_pubkey(&spk))
                            .unwrap_or(false)
                            && out.covenant_authorizing_input().unwrap_or(0) == 0
                    })
                    .collect::<Vec<_>>();
                p2sh_outputs.sort_by_key(|out| out.index);

                if p2sh_outputs.len() >= 2 {
                    let output_indexes = p2sh_outputs
                        .iter()
                        .take(2)
                        .map(|out| out.index)
                        .collect::<Vec<_>>();
                    let inferred_covenant_id = p2sh_outputs[0]
                        .canonical_covenant_id()
                        .and_then(|id| hex::decode(id).ok())
                        .filter(|bytes| bytes.len() == 32)
                        .or_else(|| {
                            compute_genesis_covenant_id_for_outputs(tx, &output_indexes)
                                .and_then(|id| hex::decode(id).ok())
                                .filter(|bytes| bytes.len() == 32)
                        });
                    let state_owner = claim_arg_text(&blob, "stateOwner")
                        .or_else(|| {
                            tx.inputs
                                .first()
                                .and_then(|input| input.previous_outpoint_script.as_deref())
                                .and_then(p2pk_owner_from_script_hex)
                        })
                        .or_else(|| {
                            tx.outputs.iter().find_map(|output| {
                                p2pk_owner_from_script_hex(&output.script_public_key)
                            })
                        });

                    if let (Some(covenant_id), Ok(state)) = (
                        inferred_covenant_id,
                        kcc20_wrapper::deploy_wrapped_root_state_from_claimed_args(
                            &blob,
                            state_owner.as_deref(),
                        ),
                    ) {
                        let root_output_index = p2sh_outputs[1].index as i32;
                        kcc20_output_states.insert(root_output_index, (covenant_id.clone(), state));
                        kcc20_touched.insert(covenant_id);
                        refresh_kcc20_markets = true;
                    }
                }
            }
        }
        let p2sh_output_count = tx
            .outputs
            .iter()
            .filter(|out| {
                hex::decode(&out.script_public_key)
                    .map(|spk| is_p2sh_script_pubkey(&spk))
                    .unwrap_or(false)
            })
            .count();

        for out in &tx.outputs {
            let spk = hex::decode(&out.script_public_key).unwrap_or_default();
            if !is_p2sh_script_pubkey(&spk) {
                continue;
            }
            let Some(script_hash) = p2sh_script_hash(&spk) else {
                continue;
            };
            let inferred_kcc20 = kcc20_output_states.get(&(out.index as i32));
            let inferred_fomo = fomo_output_states.get(&(out.index as i32));
            let inferred_snapshot = snapshot_output_states.get(&(out.index as i32));
            let explicit_binding_input = out.covenant_authorizing_input();
            let binding_input = explicit_binding_input.map(usize::from).unwrap_or(0);
            let can_infer_generic_continuation =
                explicit_binding_input.is_some() || p2sh_output_count == 1;
            let inferred_generic_continuation =
                if tx.version != 0 && explicit_binding_input.is_some() {
                    spent_covenant_ids_by_input.get(&binding_input)
                } else if tx.version != 0
                    && can_infer_generic_continuation
                    && spent_covenant_ids_by_input.len() == 1
                {
                    spent_covenant_ids_by_input.values().next()
                } else {
                    None
                };
            let covenant_id = covenant_identity_for_output(
                tx,
                out,
                &script_hash,
                inferred_kcc20
                    .map(|(id, _)| id.as_slice())
                    .or_else(|| inferred_fomo.map(|(id, _)| id.as_slice()))
                    .or_else(|| inferred_snapshot.map(|(id, _)| id.as_slice()))
                    .or_else(|| inferred_generic_continuation.map(Vec::as_slice)),
                inferred_kcc20.is_some(),
            );
            if covenant_id.as_slice() != script_hash.as_slice() {
                let fallback_matches_this_genesis: bool = sqlx::query_scalar(
                    r#"
                    SELECT EXISTS (
                        SELECT 1
                        FROM covenants
                        WHERE covenant_id = $1
                          AND script_hash = $1
                          AND genesis_txid = $2
                          AND genesis_vout = $3
                    )
                    "#,
                )
                .bind(&script_hash[..])
                .bind(&txid_bytes)
                .bind(out.index as i32)
                .fetch_one(&mut **conn)
                .await
                .context("check matching script-hash fallback covenant")?;
                if fallback_matches_this_genesis {
                    repo::rekey_covenant_id_in_tx(&mut conn, &script_hash[..], &covenant_id)
                        .await
                        .context("rekey matching script-hash fallback covenant")?;
                }
            }
            let address = out.script_public_key_address.clone().unwrap_or_default();
            let output_state = inferred_kcc20
                .map(|(_, state)| state.clone())
                .or_else(|| inferred_fomo.map(|(_, state)| state.clone()))
                .or_else(|| inferred_snapshot.map(|(_, state)| state.clone()));

            // Classify as deploy or continuation before inserting this UTXO
            // so deploy payload claims can be stored with the covenant row
            // itself, instead of as a second write on the same hot row.
            let action_kind: String = sqlx::query_scalar(
                r#"SELECT COALESCE(
                     (SELECT action FROM covenant_actions
                      WHERE covenant_id = $1 AND txid = $2
                        AND action IN ('deploy', 'continuation')
                        AND outputs->>'vout' = $3
                      ORDER BY id ASC LIMIT 1),
                     CASE WHEN EXISTS (
                       SELECT 1 FROM covenant_utxos
                       WHERE covenant_id = $1 AND txid <> $2
                     ) THEN 'continuation' ELSE 'deploy' END
                   )"#,
            )
            .bind(&covenant_id)
            .bind(&txid_bytes)
            .bind(out.index.to_string())
            .fetch_one(&mut **conn)
            .await
            .context("classify action kind")?;
            let action_kind = if wrapper_controller_output_indexes.contains(&(out.index as i32))
                || kcom_initializer_vault_output_indexes.contains(&(out.index as i32)) {
                "continuation"
            } else {
                action_kind.as_str()
            };

            let deploy_payload_claim = if action_kind == "deploy" && !wrapper_reveal_is_action {
                claim_from_payload.as_ref().and_then(|c| {
                    if is_kcc20_template(&c.tmpl) {
                        refresh_kcc20_markets = true;
                    }
                    if deploy_claims_seen.insert(covenant_id.clone()) {
                        Some((c.tmpl.clone(), claim::claimed_args_jsonb(c), c.clone()))
                    } else {
                        tracing::debug!(
                            covenant_id = %hex::encode(&covenant_id),
                            "skipped duplicate deploy payload claim in same transaction"
                        );
                        None
                    }
                })
            } else {
                None
            };

            let r = sqlx::query(
                r#"INSERT INTO covenants
                   (covenant_id, address, script_version, script_hash, template_name,
                    genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
                    claimed_template, claimed_args, claim_source)
                   VALUES ($1, $2, 0, $3, NULL, $4, $5, $6, $7, NULL, $8, $9,
                           CASE WHEN $8::TEXT IS NULL THEN NULL ELSE 'payload' END)
                   ON CONFLICT (covenant_id) DO NOTHING"#,
            )
            .bind(&covenant_id)
            .bind(&address)
            .bind(&script_hash[..])
            .bind(&txid_bytes)
            .bind(out.index as i32)
            .bind(&accepting_hash)
            .bind(block_time)
            .bind(
                deploy_payload_claim
                    .as_ref()
                    .map(|(tmpl, _, _)| tmpl.as_str()),
            )
            .bind(deploy_payload_claim.as_ref().map(|(_, blob, _)| blob))
            .execute(&mut **conn)
            .await
            .context("insert covenant")?;
            let covenant_inserted = r.rows_affected();
            stats.covenants_inserted += covenant_inserted;
            persisted_change |= covenant_inserted > 0;

            let result = sqlx::query(
                r#"INSERT INTO covenant_utxos
                   (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
                    state, created_block, spent_block, spent_by_txid, status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, 'active')
                   ON CONFLICT (txid, vout) DO UPDATE
                     SET covenant_id = EXCLUDED.covenant_id,
                         state = COALESCE(EXCLUDED.state, covenant_utxos.state)
                   WHERE covenant_utxos.covenant_id IS DISTINCT FROM EXCLUDED.covenant_id
                      OR (
                          EXCLUDED.state IS NOT NULL
                          AND covenant_utxos.state IS DISTINCT FROM EXCLUDED.state
                      )"#,
            )
            .bind(&txid_bytes)
            .bind(out.index as i32)
            .bind(&covenant_id)
            .bind(&address)
            .bind(out.amount as i64)
            .bind(&spk)
            .bind(&output_state)
            .bind(&accepting_hash)
            .execute(&mut **conn)
            .await
            .context("insert covenant utxo")?;
            let utxos_inserted = result.rows_affected();
            stats.utxos_inserted += utxos_inserted;
            persisted_change |= utxos_inserted > 0;

            // Persist payload claims as the current wallet-declared
            // constructor view. Genesis deploys set it once; continuations for
            // non-token templates can move it forward, which is how DMS
            // keepAlive exposes the latest check-in deadline.
            let mut action_decoded_args: Option<Value> = None;
            if action_kind == "deploy" {
                if let Some((tmpl, blob, c)) = deploy_payload_claim.as_ref() {
                    if covenant_inserted > 0 {
                        tracing::debug!(
                            covenant_id = %hex::encode(&covenant_id),
                            tmpl = %tmpl,
                            "stored deploy payload claim during covenant insert"
                        );
                    } else {
                        let rows_affected = Self::store_deploy_payload_claim_best_effort(
                            &mut conn,
                            tmpl,
                            blob,
                            &covenant_id,
                        )
                        .await?;
                        if rows_affected == 0 {
                            post_commit_payload_claims.push((covenant_id.clone(), c.clone()));
                        }
                    }
                }

                if p2sh_output_count == 1 {
                    if let Some(args) = api_payment_channel_open_args_from_payload.as_ref() {
                        sqlx::query(
                            r#"UPDATE covenants
                               SET template_name = 'ApiPaymentChannel',
                                   constructor_args = $1,
                                   classification_kind = 'covenant',
                                   classification_status = 'matched'
                               WHERE covenant_id = $2
                                 AND (template_name IS NULL OR template_name = 'ApiPaymentChannel')"#,
                        )
                        .bind(args)
                        .bind(&covenant_id)
                        .execute(&mut **conn)
                        .await
                        .context("classify ApiPaymentChannel open from payload")?;

                        let channel_id = hex::encode(&covenant_id);
                        upsert_indexed_api_payment_channel_open(
                            &mut **conn,
                            indexed_api_channel_open(
                                args,
                                &channel_id,
                                &self.network_id,
                                &tx.transaction_id,
                                i64::try_from(out.amount)
                                    .context("ApiPaymentChannel open amount overflows i64")?,
                                block_time,
                            )?,
                        )
                        .await
                        .context("upsert indexed ApiPaymentChannel open from payload")?;
                        action_decoded_args = Some(args.clone());
                    }
                }
            } else if action_kind == "continuation" {
                if let Some(c) = claim_from_payload.as_ref() {
                    if !is_kcc20_template(&c.tmpl) {
                        let blob = claim::claimed_args_jsonb(c);
                        sqlx::query(
                            r#"UPDATE covenants
                               SET claimed_template = $1,
                                   claimed_args = $2,
                                   claim_source = 'payload',
                                   claim_verified = CASE
                                       WHEN claimed_args IS DISTINCT FROM $2 THEN FALSE
                                       ELSE claim_verified
                                   END,
                                   claim_verified_at_ms = CASE
                                       WHEN claimed_args IS DISTINCT FROM $2 THEN NULL
                                       ELSE claim_verified_at_ms
                                   END
                               WHERE covenant_id = $3
                                 AND (claimed_template IS NULL OR claimed_template = $1)
                                 AND NOT EXISTS (
                                     SELECT 1
                                     FROM covenant_actions newer
                                     LEFT JOIN blocks newer_block
                                       ON newer_block.hash = newer.block_hash
                                     WHERE newer.covenant_id = $3
                                       AND newer.action = 'continuation'
                                       AND newer.txid <> $5
                                       AND (
                                           COALESCE(newer_block.blue_score, 0) > $4
                                           OR (
                                               COALESCE(newer_block.blue_score, 0) = $4
                                               AND newer.block_time_ms > $6
                                           )
                                       )
                                 )"#,
                        )
                        .bind(&c.tmpl)
                        .bind(&blob)
                        .bind(&covenant_id)
                        .bind(blue_score)
                        .bind(&txid_bytes)
                        .bind(block_time)
                        .execute(&mut **conn)
                        .await
                        .context("refresh claimed_template + claimed_args at continuation")?;
                        action_decoded_args = Some(blob);
                    }
                }
            }

            let outputs_json = serde_json::json!({
                "vout": out.index,
                "amountSompi": out.amount,
                "address": address,
                "scriptPubKeyHex": out.script_public_key,
                "state": output_state,
            });
            let res = sqlx::query(
                r#"INSERT INTO covenant_actions
                   (covenant_id, txid, block_hash, block_time_ms, action,
                    entrypoint, inputs, outputs, decoded_args)
                   VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, $7)
                   ON CONFLICT DO NOTHING"#,
            )
            .bind(&covenant_id)
            .bind(&txid_bytes)
            .bind(&accepting_hash)
            .bind(block_time)
            .bind(action_kind)
            .bind(&outputs_json)
            .bind(&action_decoded_args)
            .execute(&mut **conn)
            .await
            .map_err(|error| {
                classify_persist_sqlx_error("insert deploy/continuation action", error)
            })?;
            let actions_inserted = res.rows_affected();
            stats.actions_inserted += actions_inserted;
            persisted_change |= actions_inserted > 0;
            if output_state.as_ref().and_then(|state| state.get("modeName"))
                .and_then(Value::as_str).is_some_and(|name| name.starts_with("KCOM") || name == "kcom-vesting")
            {
                let updated = sqlx::query(
                    r#"UPDATE covenant_actions
                       SET outputs=jsonb_set(outputs, '{state}', $1)
                       WHERE covenant_id=$2 AND txid=$3 AND block_hash=$4
                         AND action=$5 AND outputs->>'vout'=$6
                         AND outputs->>'scriptPubKeyHex'=$7
                         AND outputs->>'amountSompi'=$8
                         AND (outputs->'state' IS NULL OR outputs->'state'='null'::jsonb
                              OR outputs->'state'=$1)"#,
                )
                .bind(&output_state)
                .bind(&covenant_id)
                .bind(&txid_bytes)
                .bind(&accepting_hash)
                .bind(action_kind)
                .bind(out.index.to_string())
                .bind(&out.script_public_key)
                .bind(out.amount.to_string())
                .execute(&mut **conn)
                .await
                .context("repair authenticated KCOM output action")?;
                anyhow::ensure!(updated.rows_affected() == 1,
                    "KCOM output action conflicts with accepted replay at {}:{} ({action_kind})",
                    tx.transaction_id, out.index);
            }
            if action_decoded_args.is_some() && action_kind == "deploy" {
                sqlx::query(
                    r#"UPDATE covenant_actions
                       SET decoded_args = COALESCE(decoded_args, $1)
                       WHERE covenant_id = $2
                         AND txid = $3
                         AND action = 'deploy'"#,
                )
                .bind(&action_decoded_args)
                .bind(&covenant_id)
                .bind(&txid_bytes)
                .execute(&mut **conn)
                .await
                .context("repair ApiPaymentChannel deploy decoded_args")?;
            }
        }

        // One indexed lookup per transaction; only conflicting outpoints need
        // correction. Normal writes do not scan historical covenant families.
        let conflicts: Vec<(i32, Vec<u8>)> = sqlx::query_as(
            "SELECT DISTINCT u.vout,u.covenant_id FROM covenant_actions a JOIN covenant_utxos u ON u.txid=a.txid AND u.vout::text=a.outputs->>'vout' WHERE a.txid=$1 AND a.action IN ('deploy','continuation') AND a.covenant_id<>u.covenant_id LIMIT 17")
            .bind(&txid_bytes).fetch_all(&mut **conn).await?;
        anyhow::ensure!(conflicts.len()<=16, "identity correction exceeds bounded outpoint limit");
        for (vout, owner) in conflicts {
            let corrections = identity::reconcile_output_actions(&mut conn, tx, vout, &owner, true).await?;
            persisted_change |= !corrections.is_empty();
        }

        if let Some((root_id, state)) = verified_fee_ticket_genesis {
            let changed = sqlx::query(
                r#"UPDATE covenants
                   SET template_name='KCC20FeeTicket', constructor_args=$1,
                       claim_verified=TRUE, claim_verified_at_ms=$2,
                       classification_kind='covenant', classification_status='matched'
                   WHERE covenant_id=$3 AND genesis_txid=$4
                     AND claimed_template='KCC20FeeTicket'
                     AND (template_name IS NULL OR template_name='KCC20FeeTicket')
                     AND (claim_verified IS DISTINCT FROM TRUE
                          OR classification_status IS DISTINCT FROM 'matched'
                          OR template_name IS DISTINCT FROM 'KCC20FeeTicket')"#,
            ).bind(&state).bind(block_time).bind(&root_id).bind(&txid_bytes)
                .execute(&mut **conn).await
                .context("verify authenticated FeeTicket genesis claim")?;
            persisted_change |= changed.rows_affected() > 0;
            covenant_summaries_touched.insert(root_id);
        }

        for (position_id, state) in authenticated_kcom_positions {
            let result = sqlx::query(
                r#"UPDATE covenants SET template_name='KCOMVesting', constructor_args=$1,
                   classification_kind='covenant', classification_status='matched'
                   WHERE covenant_id=$2 AND (template_name IS NULL OR template_name='KCOMVesting')"#,
            ).bind(&state).bind(&position_id).execute(&mut **conn).await
                .context("classify authenticated campaign vesting position")?;
            anyhow::ensure!(result.rows_affected() == 1, "campaign position classification conflict");
            persisted_change = true;
            covenant_summaries_touched.insert(position_id);
        }

        if let Some(snapshot) = snapshot_start_token {
            let result = sqlx::query(
                r#"UPDATE covenants
                   SET template_name = 'KCC20',
                       constructor_args = $1,
                       claimed_template = 'KCC20',
                       claimed_args = $2,
                       claim_source = $3,
                       claim_verified = TRUE,
                       claim_verified_at_ms = $4,
                       classification_kind = 'covenant',
                       classification_status = 'matched'
                   WHERE covenant_id = $5
                     AND (template_name IS NULL OR template_name = 'KCC20')
                     AND (claimed_template IS NULL OR claimed_template = 'KCC20')"#,
            )
            .bind(&snapshot.constructor)
            .bind(&snapshot.claimed_args)
            .bind(snapshot.claim_source)
            .bind(block_time)
            .bind(&snapshot.token_id)
            .execute(&mut **conn)
            .await
            .context("classify signerless snapshot KCC20 genesis")?;
            anyhow::ensure!(
                result.rows_affected() == 1,
                "signerless snapshot token covenant could not be classified"
            );
            persisted_change = true;
            covenant_summaries_touched.insert(snapshot.token_id.clone());

            let result = sqlx::query(
                r#"UPDATE covenant_actions
                   SET decoded_args = COALESCE(decoded_args, '{}'::jsonb) || $1
                   WHERE covenant_id = $2
                     AND txid = $3
                     AND action = 'deploy'"#,
            )
            .bind(&snapshot.action_args)
            .bind(&snapshot.token_id)
            .bind(&txid_bytes)
            .execute(&mut **conn)
            .await
            .context("annotate signerless snapshot KCC20 deploy action")?;
            persisted_change |= result.rows_affected() > 0;
        }

        if persisted_change && !kcc20_touched.is_empty() {
            refresh_kcc20_markets = true;
        }
        repo::refresh_action_canonical_token_ids_for_tx(&mut conn, &txid_bytes)
            .await
            .context("refresh KCC20 action canonical token ids")?;
        if persisted_change {
            for covenant_id in kcc20_touched {
                refresh_kcc20_holders(&mut conn, &covenant_id, block_time).await?;
            }
        }
        refresh_kcc20_markets &= persisted_change;
        if refresh_kcc20_markets {
            repo::mark_kcc20_projection_dirty_tx(&mut conn, "kcc20_persist", Some(&txid_bytes))
                .await
                .context("mark KCC20 projections dirty after persist")?;
        }
        for covenant_id in covenant_summaries_touched {
            sqlx::query("SELECT finalize_deferred_covenant_summary($1)")
                .bind(covenant_id)
                .execute(&mut **conn)
                .await
                .context("finalize deferred covenant summary")?;
        }

        deferred_decode::finish(&mut conn,tx,deferred_reason.as_deref(),&deferred_families,replay_deferred).await?;
        Ok((stats, refresh_kcc20_markets, post_commit_payload_claims))
    }

}

async fn refresh_kcc20_holders(
    conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    covenant_id: &[u8],
    block_time_ms: i64,
) -> Result<()> {
    sqlx::query("DELETE FROM kcc20_holders WHERE covenant_id = $1")
        .bind(covenant_id)
        .execute(&mut **conn)
        .await
        .context("delete stale KCC20 holder rows")?;

    sqlx::query(
        r#"
        INSERT INTO kcc20_holders
            (covenant_id, owner_identifier, identifier_type, amount_total,
             utxo_count, is_minter, last_change_ms)
        SELECT
            covenant_id,
            decode(state->>'owner', 'hex')           AS owner_identifier,
            (state->>'ownerScheme')::SMALLINT        AS identifier_type,
            SUM((state->>'amount')::NUMERIC)        AS amount_total,
            COUNT(*)::INT                           AS utxo_count,
            COALESCE((state->>'isMintAuthority')::BOOLEAN, FALSE) AS is_minter,
            $2                                      AS last_change_ms
        FROM covenant_utxos
        WHERE covenant_id = $1
          AND status = 'active'
          AND state ? 'owner'
          AND state ? 'ownerScheme'
          AND state ? 'amount'
          AND (NOT state ? 'mode' OR state->>'mode' = '0')
        GROUP BY covenant_id, owner_identifier, identifier_type, is_minter
        "#,
    )
    .bind(covenant_id)
    .bind(block_time_ms)
    .execute(&mut **conn)
    .await
    .context("refresh KCC20 holder rows")?;

    Ok(())
}

async fn covenant_input_amount_sompi(
    conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &tn12_indexer_core::RestTxInput,
    prev_txid: &[u8],
    prev_vout: i32,
) -> Result<i64> {
    if let Some(amount) = input.previous_outpoint_amount {
        return i64::try_from(amount).context("ApiPaymentChannel input amount overflows i64");
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT amount_sompi FROM covenant_utxos WHERE txid = $1 AND vout = $2",
    )
    .bind(prev_txid)
    .bind(prev_vout)
    .fetch_optional(&mut **conn)
    .await
    .context("lookup covenant input amount")?
    .context("ApiPaymentChannel input amount missing")
}

async fn covenant_genesis_txid_hex(
    conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    covenant_id: &[u8],
) -> Result<Option<String>> {
    sqlx::query_scalar::<_, String>(
        "SELECT encode(genesis_txid, 'hex') FROM covenants WHERE covenant_id = $1",
    )
    .bind(covenant_id)
    .fetch_optional(&mut **conn)
    .await
    .context("lookup covenant genesis txid")
}

fn indexed_api_channel_open(
    args: &Value,
    channel_id: &str,
    network_id: &str,
    open_txid_hex: &str,
    deposit_sompi: i64,
    indexed_at_ms: i64,
) -> Result<IndexedApiPaymentChannelOpen> {
    Ok(IndexedApiPaymentChannelOpen {
        channel_id: channel_id.to_string(),
        network_id: network_id.to_string(),
        payer_pubkey: json_hex(args, "payerPubkey")?,
        provider_pubkey: json_hex(args, "providerPubkey")?,
        provider_payout_pubkey: json_hex(args, "providerPayoutPubkey")?,
        voucher_domain_hash: json_hex(args, "voucherDomainHash")?,
        deposit_sompi,
        reserve_sompi: json_i64(args, "reserveSompi")?,
        max_spend_sompi: json_i64(args, "maxSpendSompi")?,
        refund_after_ms: json_i64(args, "refundAfterMs")?,
        close_after_ms: json_i64(args, "closeAfterMs").unwrap_or(0),
        open_txid_hex: open_txid_hex.to_string(),
        indexed_at_ms,
    })
}

fn parse_api_payment_channel_open_payload(payload_hex: &str) -> Option<Value> {
    let bytes = hex::decode(payload_hex).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let root: Value = serde_json::from_str(text).ok()?;
    let payment = root.get("kaspaApiPayment")?;
    if payment.get("v").and_then(Value::as_u64)? != 1 {
        return None;
    }
    if payment.get("action").and_then(Value::as_str)? != "channel_open" {
        return None;
    }
    if payment.get("contract").and_then(Value::as_str)? != "ApiPaymentChannel" {
        return None;
    }

    let mut args = serde_json::Map::new();
    for key in [
        "payerPubkey",
        "providerPubkey",
        "providerPayoutPubkey",
        "voucherDomainHash",
        "refundAfterMs",
        "reserveSompi",
        "maxSpendSompi",
    ] {
        args.insert(key.to_string(), payment.get(key)?.clone());
    }
    Some(Value::Object(args))
}

fn json_hex(args: &Value, key: &str) -> Result<String> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("ApiPaymentChannel constructor arg {key} missing"))?;
    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        anyhow::bail!("ApiPaymentChannel constructor arg {key} is not hex");
    }
    Ok(value.to_ascii_lowercase())
}

fn json_i64(args: &Value, key: &str) -> Result<i64> {
    let value = args
        .get(key)
        .with_context(|| format!("ApiPaymentChannel constructor arg {key} missing"))?;
    if let Some(n) = value.as_i64() {
        return Ok(n);
    }
    if let Some(n) = value.as_u64() {
        return i64::try_from(n)
            .with_context(|| format!("ApiPaymentChannel constructor arg {key} overflows i64"));
    }
    if let Some(s) = value.as_str() {
        return s
            .parse::<i64>()
            .with_context(|| format!("ApiPaymentChannel constructor arg {key} is not an i64"));
    }
    anyhow::bail!("ApiPaymentChannel constructor arg {key} is not an i64")
}

async fn upsert_inferred_kcc20_outputs(
    conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tx: &RestTransaction,
    accepting_hash: &[u8],
    covenant_id: &[u8],
    output_states: &[(i32, Value)],
) -> Result<u64> {
    let txid_bytes = hex::decode(&tx.transaction_id)
        .with_context(|| format!("decoding txid {}", tx.transaction_id))?;

    let mut rows_affected = 0;
    for (output_index, state) in output_states {
        let Some(out) = tx
            .outputs
            .iter()
            .find(|out| out.index as i32 == *output_index)
        else {
            continue;
        };
        let spk = hex::decode(&out.script_public_key).unwrap_or_default();
        if !is_p2sh_script_pubkey(&spk) {
            continue;
        }
        let address = out.script_public_key_address.clone().unwrap_or_default();

        let result = sqlx::query(
            r#"INSERT INTO covenant_utxos
               (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
                state, created_block, spent_block, spent_by_txid, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, 'active')
               ON CONFLICT (txid, vout) DO UPDATE
                 SET covenant_id = EXCLUDED.covenant_id,
                     state = EXCLUDED.state
               WHERE covenant_utxos.covenant_id IS DISTINCT FROM EXCLUDED.covenant_id
                  OR covenant_utxos.state IS DISTINCT FROM EXCLUDED.state"#,
        )
        .bind(&txid_bytes)
        .bind(*output_index)
        .bind(covenant_id)
        .bind(address)
        .bind(out.amount as i64)
        .bind(spk)
        .bind(state)
        .bind(accepting_hash)
        .execute(&mut **conn)
        .await
        .context("upsert inferred KCC20 output utxo")?;
        rows_affected += result.rows_affected();
    }

    Ok(rows_affected)
}

fn json_text_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| json_text(value.get(*key)?))
}

fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn json_i32(value: Option<&Value>) -> Option<i32> {
    let value = value?;
    match value {
        Value::Number(number) => number
            .as_i64()
            .and_then(|number| i32::try_from(number).ok()),
        Value::String(number) => number.parse::<i32>().ok(),
        _ => None,
    }
}

fn snapshot_controller_transition_successor(
    tx: &RestTransaction,
    input_index: usize,
    covenant_id: &[u8],
    transition: &Value,
) -> Result<Option<(i32, Value)>> {
    let next_state = transition
        .get("nextState")
        .context("snapshot transition is missing nextState")?;
    let expected_authorizing_input =
        u16::try_from(input_index).context("snapshot controller input index exceeds u16")?;

    if transition.get("action").and_then(Value::as_str) == Some("start") {
        anyhow::ensure!(!next_state.is_null(), "snapshot start successor is missing");
        let reserve_output_index = json_i32(transition.get("reserveOutputIndex"))
            .context("snapshot start reserve output index is missing")?;
        let controller_output_index = json_i32(transition.get("controllerOutputIndex"))
            .context("snapshot start controller output index is missing")?;
        let reserve_output_index = u64::try_from(reserve_output_index)
            .context("snapshot start reserve output index is negative")?;
        let controller_output_index_u64 = u64::try_from(controller_output_index)
            .context("snapshot start controller output index is negative")?;
        anyhow::ensure!(
            reserve_output_index != controller_output_index_u64,
            "snapshot start reserve and controller outputs alias"
        );

        let reserve_output = tx
            .outputs
            .iter()
            .find(|output| output.index == reserve_output_index)
            .context("snapshot start reserve output is missing")?;
        let controller_output = tx
            .outputs
            .iter()
            .find(|output| output.index == controller_output_index_u64)
            .context("snapshot start controller successor is missing")?;
        for (role, output) in [
            ("reserve", reserve_output),
            ("controller", controller_output),
        ] {
            if let Some(authorizing_input) = output.covenant_authorizing_input() {
                anyhow::ensure!(
                    authorizing_input == expected_authorizing_input,
                    "snapshot start {role} output has the wrong authorizing input"
                );
            }
        }
        if let Some(actual_id) = controller_output.canonical_covenant_id() {
            let actual_id =
                hex::decode(actual_id).context("decode snapshot controller successor id")?;
            anyhow::ensure!(
                actual_id == covenant_id,
                "snapshot start controller successor has the wrong covenant id"
            );
        }
        anyhow::ensure!(
            tx.outputs.iter().all(|output| {
                output.covenant_authorizing_input() != Some(expected_authorizing_input)
                    || output.index == reserve_output_index
                    || output.index == controller_output_index_u64
            }),
            "snapshot start controller input authorizes an unexpected output"
        );
        let controller_cell_sompi = next_state
            .get("controllerCellKas")
            .and_then(json_text)
            .context("snapshot start controller cell value is missing")?
            .parse::<u64>()
            .context("parse snapshot start controller cell value")?;
        let reserve_cell_sompi = next_state
            .get("reserveCellKas")
            .and_then(json_text)
            .context("snapshot start reserve cell value is missing")?
            .parse::<u64>()
            .context("parse snapshot start reserve cell value")?;
        anyhow::ensure!(
            controller_output.amount == controller_cell_sompi,
            "snapshot start controller successor has the wrong cell value"
        );
        anyhow::ensure!(
            reserve_output.amount == reserve_cell_sompi,
            "snapshot start reserve output has the wrong cell value"
        );
        return Ok(Some((controller_output_index, next_state.clone())));
    }

    let successors = tx
        .outputs
        .iter()
        .filter(|output| {
            output.covenant_authorizing_input() == Some(expected_authorizing_input)
                && output
                    .canonical_covenant_id()
                    .and_then(|id| hex::decode(id).ok())
                    .is_some_and(|id| id == covenant_id)
        })
        .collect::<Vec<_>>();
    let controller_authorized_output_count = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(expected_authorizing_input))
        .count();
    if next_state.is_null() {
        anyhow::ensure!(
            controller_authorized_output_count == 0,
            "terminal snapshot claim must not create a controller successor"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        successors.len() == 1 && controller_authorized_output_count == 1,
        "nonterminal snapshot claim must create exactly one role-correct controller successor"
    );
    Ok(Some((successors[0].index as i32, next_state.clone())))
}

struct SnapshotStartKcc20Projection {
    token_id: Vec<u8>,
    output_states: Vec<(i32, Value)>,
    constructor: Value,
    claimed_args: Value,
    claim_source: &'static str,
    action_args: Value,
}

fn project_snapshot_start_kcc20(
    tx: &RestTransaction,
    start: &Value,
    payload_claim: Option<&claim::ClaimedDeployment>,
    template_prefix: &[u8],
    template_suffix: &[u8],
) -> Result<SnapshotStartKcc20Projection> {
    let token_id_hex = start
        .get("tokenId")
        .and_then(Value::as_str)
        .context("snapshot start tokenId is missing")?
        .to_ascii_lowercase();
    let token_id = hex::decode(&token_id_hex).context("decode snapshot start tokenId")?;
    anyhow::ensure!(
        token_id.len() == 32,
        "snapshot start tokenId is not 32 bytes"
    );
    let reserves = start
        .get("reserves")
        .and_then(Value::as_array)
        .context("snapshot start reserves are missing")?;
    anyhow::ensure!(
        !reserves.is_empty() && reserves.len() <= 8,
        "snapshot start reserve count is invalid"
    );
    let reserve_cell_sompi = start
        .get("reserveCellKas")
        .and_then(json_text)
        .context("snapshot start reserveCellKas is missing")?
        .parse::<u64>()
        .context("parse snapshot reserveCellKas")?;
    let total_supply = start
        .get("totalSupply")
        .and_then(json_text)
        .context("snapshot start totalSupply is missing")?
        .parse::<i128>()
        .context("parse snapshot totalSupply")?;
    let output_indexes = (0..reserves.len())
        .map(|index| u64::try_from(index).expect("snapshot shard index fits u64"))
        .collect::<Vec<_>>();
    let derived_token_id = compute_genesis_covenant_id_for_outputs_at_input(tx, 1, &output_indexes)
        .context("derive snapshot token covenant id from controller input")?;
    anyhow::ensure!(
        derived_token_id.eq_ignore_ascii_case(&token_id_hex),
        "snapshot start tokenId does not match its KIP-20 genesis group"
    );
    let template_script = kcc20_standard::script_for_state_value_with_template_parts(
        &reserves[0],
        template_prefix,
        template_suffix,
    )?;
    let template_hash = tn12_indexer_decoder::token_profiles::template_hash(
        &template_script,
        template_prefix.len(),
    )?;
    anyhow::ensure!(
        start
            .get("kcc20TemplateHash")
            .and_then(Value::as_str)
            .is_some_and(|expected| hex::encode(template_hash).eq_ignore_ascii_case(expected)),
        "snapshot start KCC20 template witness does not match its committed hash"
    );

    let mut output_states = Vec::with_capacity(reserves.len());
    let mut projected_total = 0_i128;
    for (index, reserve) in reserves.iter().enumerate() {
        let output_index = u64::try_from(index).expect("snapshot shard index fits u64");
        let output = tx
            .outputs
            .iter()
            .find(|output| output.index == output_index)
            .with_context(|| format!("snapshot reserve output {index} is missing"))?;
        anyhow::ensure!(
            output.amount == reserve_cell_sompi,
            "snapshot reserve output {index} has the wrong cell value"
        );
        if let Some(authorizing_input) = output.covenant_authorizing_input() {
            anyhow::ensure!(
                authorizing_input == 1,
                "snapshot reserve output {index} is not authorized by controller input 1"
            );
        }
        if let Some(covenant_id) = output.canonical_covenant_id() {
            anyhow::ensure!(
                covenant_id.eq_ignore_ascii_case(&token_id_hex),
                "snapshot reserve output {index} has the wrong canonical token id"
            );
        }
        let script = kcc20_standard::script_for_state_value_with_template_parts(
            reserve,
            template_prefix,
            template_suffix,
        )
        .with_context(|| format!("reconstruct snapshot reserve {index} KCC20 script"))?;
        let script_public_key = hex::decode(&output.script_public_key)
            .with_context(|| format!("decode snapshot reserve output {index} script"))?;
        let actual_script_hash = p2sh_script_hash(&script_public_key)
            .with_context(|| format!("snapshot reserve output {index} is not P2SH"))?;
        anyhow::ensure!(
            actual_script_hash == blake2b_256(&script),
            "snapshot reserve output {index} does not match its decoded KCC20 state"
        );
        let amount = reserve
            .get("amount")
            .and_then(json_text)
            .context("snapshot reserve amount is missing")?
            .parse::<i128>()
            .context("parse snapshot reserve amount")?;
        projected_total = projected_total
            .checked_add(amount)
            .context("snapshot reserve total overflows")?;
        output_states.push((i32::try_from(index)?, reserve.clone()));
    }
    anyhow::ensure!(
        projected_total == total_supply,
        "snapshot reserve outputs do not conserve total supply"
    );
    anyhow::ensure!(
        tx.outputs.iter().all(|output| {
            !output
                .canonical_covenant_id()
                .is_some_and(|id| id.eq_ignore_ascii_case(&token_id_hex))
                || output_indexes.contains(&output.index)
        }),
        "snapshot start contains an extra canonical token-family output"
    );

    let verified_payload = payload_claim
        .filter(|claimed| snapshot_start_payload_claim_matches(start, claimed))
        .map(claim::claimed_args_jsonb);
    let (claimed_args, claim_source) = match verified_payload {
        Some(claimed_args) => (claimed_args, "snapshot-start-payload"),
        None => (synthetic_snapshot_start_claim(start), "snapshot-start"),
    };
    let first_state = output_states
        .first()
        .map(|(_, state)| state.clone())
        .context("snapshot start has no reserve state")?;
    let constructor = serde_json::json!({
        "standard": "KCC20",
        "templateHash": start.get("kcc20TemplateHash").cloned().unwrap_or(Value::Null),
        "state": first_state,
        "snapshot": {
            "migrationId": start.get("migrationId").cloned().unwrap_or(Value::Null),
            "manifestCommitment": start.get("manifestCommitment").cloned().unwrap_or(Value::Null),
            "holderExtensionCommitment": start.get("holderExtensionCommitment").cloned().unwrap_or(Value::Null),
            "totalSupply": start.get("totalSupply").cloned().unwrap_or(Value::Null),
            "reserveCount": reserves.len().to_string(),
        },
    });
    let action_args = serde_json::json!({
        "projectionSchema": "kcc20-snapshot-token-genesis/v1",
        "canonicalTokenId": token_id_hex,
        "migrationId": start.get("migrationId").cloned().unwrap_or(Value::Null),
        "manifestCommitment": start.get("manifestCommitment").cloned().unwrap_or(Value::Null),
        "holderExtensionCommitment": start.get("holderExtensionCommitment").cloned().unwrap_or(Value::Null),
        "totalSupply": start.get("totalSupply").cloned().unwrap_or(Value::Null),
        "reserves": reserves,
        "metadataSource": claim_source,
    });
    Ok(SnapshotStartKcc20Projection {
        token_id,
        output_states,
        constructor,
        claimed_args,
        claim_source,
        action_args,
    })
}

fn snapshot_start_payload_claim_matches(start: &Value, claimed: &claim::ClaimedDeployment) -> bool {
    if claimed.tmpl != "KCC20" {
        return false;
    }
    let blob = claim::claimed_args_jsonb(claimed);
    let expected_extension = start
        .get("holderExtensionCommitment")
        .and_then(Value::as_str);
    let expected_total = start.get("totalSupply").and_then(json_text);
    let expected_migration = start.get("migrationId").and_then(Value::as_str);
    let expected_manifest = start.get("manifestCommitment").and_then(Value::as_str);
    let Some((expected_extension, expected_total, expected_migration, expected_manifest)) =
        expected_extension
            .zip(expected_total)
            .zip(expected_migration)
            .zip(expected_manifest)
            .map(|(((extension, total), migration), manifest)| {
                (extension, total, migration, manifest)
            })
    else {
        return false;
    };
    let Ok(deploy_states) = kcc20_standard::deploy_output_states_from_claimed_args(&blob) else {
        return false;
    };
    let calculated_extension = deploy_states.first().and_then(|output| {
        output
            .state
            .get("extensionCommitment")
            .and_then(Value::as_str)
    });
    let claimed_max_supply =
        kcc20_standard::decode_supply_claim(&blob, "maxSupply").map(|value| value.to_string());
    let claimed_premint_supply = kcc20_standard::decode_supply_claim(&blob, "premintSupply")
        .map(|value| value.to_string());
    if calculated_extension != Some(expected_extension)
        || claim_arg_text(&blob, "holderExtensionCommitment").as_deref() != Some(expected_extension)
        || claimed_max_supply.as_deref() != Some(expected_total.as_str())
        || claimed_premint_supply.as_deref() != Some(expected_total.as_str())
        || claim_arg_text(&blob, "mintPolicy").as_deref() != Some("0")
        || claim_arg_text(&blob, "mintLaneCount").as_deref() != Some("1")
        || claim_arg_text(&blob, "snapshotMigrationId").as_deref() != Some(expected_migration)
        || claim_arg_text(&blob, "snapshotManifestCommitment").as_deref() != Some(expected_manifest)
    {
        return false;
    }
    let Some(claimed_reserves) =
        claim_arg_value(&blob, "snapshotReserves").and_then(Value::as_array)
    else {
        return false;
    };
    let Some(expected_reserves) = start.get("reserves").and_then(Value::as_array) else {
        return false;
    };
    if claimed_reserves.len() != expected_reserves.len() {
        return false;
    }
    claimed_reserves
        .iter()
        .zip(expected_reserves)
        .enumerate()
        .all(|(index, (actual, expected))| {
            json_text_any(actual, &["shardIndex"]).and_then(|value| value.parse::<usize>().ok())
                == Some(index)
                && json_text_any(actual, &["amount"]) == json_text_any(expected, &["amount"])
                && json_text_any(actual, &["owner"]) == json_text_any(expected, &["owner"])
                && json_text_any(actual, &["ownerScheme"])
                    == json_text_any(expected, &["ownerScheme"])
        })
}

/// Reconstruct only a complete genesis group whose claimed scripts open the
/// accepted outputs. Equal mint-lane scripts must consume distinct vouts.
fn claimed_genesis_states(
    tx: &RestTransaction,
    claimed: &claim::ClaimedDeployment,
) -> Result<Option<(Vec<u8>, Vec<(i32, Value)>)>> {
    let blob = claim::claimed_args_jsonb(claimed);
    let expected = match claimed.tmpl.as_str() {
        "KCC20" => kcc20_standard::deploy_output_states_from_claimed_args(&blob)?
            .into_iter()
            .map(|output| (output.script_hash, output.state))
            .collect::<Vec<_>>(),
        "KCC20FeeTicket" => {
            let (hash, state) = kcc20_fee_ticket::deploy_root_state_from_claimed_args(&blob)?;
            vec![(hash, state)]
        }
        _ => return Ok(None),
    };
    anyhow::ensure!(!expected.is_empty(), "deploy claim has no outputs");

    let mut matched = assign_claimed_genesis_outputs(tx, expected)?;
    matched.sort_by_key(|(output, _)| output.index);
    let indexes = matched.iter().map(|(output, _)| output.index).collect::<Vec<_>>();
    let bound_inputs = matched.iter()
        .filter_map(|(output, _)| output.covenant_authorizing_input())
        .collect::<HashSet<_>>();
    anyhow::ensure!(bound_inputs.len() <= 1, "deploy outputs disagree on authorizing input");
    let known_input = bound_inputs.iter().next().copied().map(usize::from);
    let computed = known_input.or_else(|| {
        // An explicit canonical ID remains authoritative when REST omits the
        // binding. Input zero is only a fallback when no ID is exposed.
        matched.iter().all(|(output, _)| output.canonical_covenant_id().is_none())
            .then_some(0)
    }).and_then(|input| compute_genesis_covenant_id_for_outputs_at_input(tx, input, &indexes))
        .and_then(|id| hex::decode(id).ok())
        .filter(|id| id.len() == 32);
    let mut explicit = None;
    for (output, _) in &matched {
        if let Some(id) = output.canonical_covenant_id() {
            let bytes = hex::decode(id)?;
            anyhow::ensure!(bytes.len() == 32, "invalid output covenant id");
            anyhow::ensure!(
                explicit.as_ref().is_none_or(|known| known == &bytes),
                "deploy outputs disagree on canonical covenant id"
            );
            explicit = Some(bytes);
        }
    }
    if let (Some(actual), Some(calculated)) = (&explicit, &computed) {
        anyhow::ensure!(actual == calculated, "deploy output covenant id mismatch");
    }
    let covenant_id = explicit.or(computed).ok_or_else(|| anyhow::anyhow!(
        "cannot derive deploy covenant id"
    ))?;
    let states = matched
        .into_iter()
        .map(|(output, state)| Ok((i32::try_from(output.index)?, state)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some((covenant_id, states)))
}

fn assign_claimed_genesis_outputs(
    tx: &RestTransaction,
    expected: Vec<([u8; 32], Value)>,
) -> Result<Vec<(&RestTxOutput, Value)>> {
    let mut candidates: HashMap<[u8; 32], Vec<&RestTxOutput>> = HashMap::new();
    for output in &tx.outputs {
        if let Some(hash) = hex::decode(&output.script_public_key)
            .ok()
            .and_then(|script| p2sh_script_hash(&script))
        {
            candidates.entry(hash).or_default().push(output);
        }
    }
    for outputs in candidates.values_mut() {
        outputs.sort_by_key(|output| output.index);
    }
    let mut expected_counts: HashMap<[u8; 32], usize> = HashMap::new();
    for (hash, _) in &expected {
        *expected_counts.entry(*hash).or_default() += 1;
    }
    for (hash, count) in expected_counts {
        anyhow::ensure!(
            candidates.get(&hash).map_or(0, Vec::len) == count,
            "deploy claim output multiplicity does not match accepted transaction"
        );
    }

    let mut matched = Vec::with_capacity(expected.len());
    for (hash, state) in expected {
        let output = candidates
            .get_mut(&hash)
            .and_then(|outputs| (!outputs.is_empty()).then(|| outputs.remove(0)))
            .ok_or_else(|| anyhow::anyhow!("deploy claim output was already consumed"))?;
        matched.push((output, state));
    }
    let indexes = matched.iter().map(|(output, _)| output.index).collect::<Vec<_>>();
    anyhow::ensure!(
        indexes.iter().copied().collect::<HashSet<_>>().len() == indexes.len(),
        "deploy claim selected a duplicate vout"
    );
    Ok(matched)
}

fn claim_arg_value<'a>(claimed_args: &'a Value, name: &str) -> Option<&'a Value> {
    let args = claimed_args.get("args")?;
    match args {
        Value::Array(items) => items
            .iter()
            .find_map(|item| (item.get("name")?.as_str()? == name).then(|| item.get("value"))?),
        Value::Object(map) => map.get(name),
        _ => None,
    }
}

fn synthetic_snapshot_start_claim(start: &Value) -> Value {
    let reserves = start.get("reserves").cloned().unwrap_or(Value::Null);
    let arg = |name: &str, arg_type: &str, value: Value| serde_json::json!({"name": name, "type": arg_type, "value": value});
    serde_json::json!({
        "tmpl": "KCC20",
        "args": [
            arg("maxSupply", "u128", start.get("totalSupply").cloned().unwrap_or(Value::Null)),
            arg("premintSupply", "u128", start.get("totalSupply").cloned().unwrap_or(Value::Null)),
            arg("mintLaneCount", "u64", Value::String("1".into())),
            arg("mintPolicy", "u64", Value::String("0".into())),
            arg("holderExtensionCommitment", "byte[32]", start.get("holderExtensionCommitment").cloned().unwrap_or(Value::Null)),
            arg("snapshotMigrationId", "byte[32]", start.get("migrationId").cloned().unwrap_or(Value::Null)),
            arg("snapshotManifestCommitment", "byte[32]", start.get("manifestCommitment").cloned().unwrap_or(Value::Null)),
            arg("snapshotReserves", "object", reserves),
        ],
        "meta": {
            "description": "Verified signerless snapshot start; metadata opening was not present in the historical transaction"
        }
    })
}

fn merge_json_object(target: &mut Option<Value>, source: Value) {
    let Some(source_object) = source.as_object() else {
        return;
    };
    if target.is_none() {
        *target = Some(Value::Object(serde_json::Map::new()));
    }
    let Some(target_object) = target.as_mut().and_then(Value::as_object_mut) else {
        return;
    };
    for (key, value) in source_object {
        target_object.insert(key.clone(), value.clone());
    }
}

fn claim_arg_text(claimed_args: &Value, name: &str) -> Option<String> {
    if let Some(value) = claimed_args.get(name).and_then(json_text) {
        return Some(value);
    }
    let args = claimed_args.get("args")?;
    match args {
        Value::Array(items) => items.iter().find_map(|item| {
            (item.get("name")?.as_str()? == name).then(|| json_text(item.get("value")?))?
        }),
        Value::Object(map) => map.get(name).and_then(json_text),
        _ => None,
    }
}

fn snapshot_state_from_claimed_args(claimed_args: &Value) -> Option<Value> {
    let state = match claimed_args.get("args")? {
        Value::Array(items) => items.iter().find_map(|item| {
            (item.get("name")?.as_str()? == "controllerState")
                .then(|| item.get("value").cloned())?
        }),
        Value::Object(map) => map.get("controllerState").cloned(),
        _ => None,
    }?;
    let object = state.as_object()?;
    const HEX_32_FIELDS: [&str; 6] = [
        "tokenId",
        "holderExtensionCommitment",
        "manifestCommitment",
        "snapshotContext",
        "kcc20TemplateHash",
        "remainingRoot",
    ];
    const INTEGER_FIELDS: [&str; 12] = [
        "claimNotBeforeDaaScore",
        "shardIndex",
        "globalIndexStart",
        "holderCount",
        "treeDepth",
        "kcc20TemplatePrefixLen",
        "kcc20TemplateSuffixLen",
        "controllerCellKas",
        "reserveCellKas",
        "recipientMinCellKas",
        "remainingAmount",
        "claimsProcessed",
    ];
    if !HEX_32_FIELDS.iter().all(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() == 64 && hex::decode(value).is_ok())
    }) || !INTEGER_FIELDS.iter().all(|field| {
        object
            .get(*field)
            .and_then(json_text)
            .and_then(|value| value.parse::<i64>().ok())
            .is_some_and(|value| value >= 0)
    }) {
        return None;
    }
    Some(state)
}

fn p2pk_owner_from_script_hex(script_hex: &str) -> Option<String> {
    let normalized = script_hex.trim().to_ascii_lowercase();
    let script = normalized.strip_prefix("0000").unwrap_or(&normalized);
    if script.len() == 68
        && script.starts_with("20")
        && script.ends_with("ac")
        && script[2..66].as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        Some(script[2..66].to_string())
    } else {
        None
    }
}

pub fn redeem_script_fingerprint(reveal: &[u8]) -> [u8; 32] {
    blake2b_256(reveal)
}

pub fn json_or_null<T: serde::Serialize>(v: Option<&T>) -> Value {
    v.map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
        .unwrap_or(Value::Null)
}

fn covenant_identity_for_output(
    tx: &tn12_indexer_core::RestTransaction,
    out: &tn12_indexer_core::RestTxOutput,
    script_hash: &[u8; 32],
    inferred_continuation_id: Option<&[u8]>,
    prefer_inferred_id: bool,
) -> Vec<u8> {
    let explicit_id = out
        .canonical_covenant_id()
        .and_then(|id| hex::decode(id).ok())
        .filter(|bytes| bytes.len() == 32);
    let inferred_id = inferred_continuation_id.map(|id| id.to_vec());
    let primary_id = if prefer_inferred_id {
        inferred_id.or(explicit_id)
    } else {
        explicit_id.or(inferred_id)
    };

    primary_id
        .or_else(|| {
            compute_genesis_covenant_id_for_output(tx, out.index)
                .and_then(|id| hex::decode(id).ok())
                .filter(|bytes| bytes.len() == 32)
        })
        .unwrap_or_else(|| script_hash.to_vec())
}

fn decode_kcc20_orderbook_merge_output(
    tx: &RestTransaction,
    primary_input_index: usize,
    primary_signature_script: &[u8],
    primary_reveal_script: &[u8],
    covenant_id: &[u8],
    spent_covenant_ids_by_input: &HashMap<usize, Vec<u8>>,
) -> Result<Option<(i32, Value)>> {
    let Some(request) = kcc20_orderbook::decode_primary_merge_request(primary_signature_script)?
    else {
        return Ok(None);
    };
    let mut peers = Vec::new();
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input_index == primary_input_index
            || spent_covenant_ids_by_input
                .get(&input_index)
                .map(Vec::as_slice)
                != Some(covenant_id)
        {
            continue;
        }
        let signature_script = hex::decode(&input.signature_script)
            .context("decode KCC20Orderbook input signature script")?;
        let reveal_script = extract_last_push(&signature_script)
            .context("KCC20Orderbook merge member reveal script is missing")?;
        peers.push((input_index, reveal_script));
    }
    let (output_index, state, script_hash) = kcc20_orderbook::decode_merge_output_state_value(
        primary_input_index,
        primary_signature_script,
        primary_reveal_script,
        &peers,
    )?
    .context("KCC20Orderbook primary merge did not produce output state")?;
    let peer_input_indexes = peers.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    validate_merge_output_binding(
        tx,
        request.merged_output_index,
        primary_input_index,
        &peer_input_indexes,
        covenant_id,
        &script_hash,
    )?;

    Ok(Some((output_index, state)))
}

fn validate_merge_output_binding(
    tx: &RestTransaction,
    output_index: i32,
    primary_input_index: usize,
    peer_input_indexes: &[usize],
    covenant_id: &[u8],
    expected_script_hash: &[u8; 32],
) -> Result<()> {
    let output_index = u64::try_from(output_index).context("merge output index is negative")?;
    let mut matching_outputs = tx
        .outputs
        .iter()
        .filter(|output| output.index == output_index);
    let output = matching_outputs
        .next()
        .context("merge output is outside the transaction")?;
    if matching_outputs.next().is_some() {
        anyhow::bail!("merge output index is duplicated");
    }
    let explicit_covenant_id = output
        .canonical_covenant_id()
        .context("merge output has no explicit covenant id")?;
    let explicit_covenant_id =
        hex::decode(explicit_covenant_id).context("decode merge output covenant id")?;
    if explicit_covenant_id != covenant_id {
        anyhow::bail!("merge output covenant id does not match the spent covenant");
    }
    let expected_authorizing_input =
        u16::try_from(primary_input_index).context("primary merge input index exceeds u16")?;
    if output.covenant_authorizing_input() != Some(expected_authorizing_input) {
        anyhow::bail!("merge output is not authorized by the primary merge input");
    }
    let primary_authorized_outputs = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(expected_authorizing_input))
        .count();
    if primary_authorized_outputs != 1 {
        anyhow::bail!("primary merge input must authorize exactly one output");
    }
    for peer_input_index in peer_input_indexes {
        let peer_input_index =
            u16::try_from(*peer_input_index).context("peer merge input index exceeds u16")?;
        if tx
            .outputs
            .iter()
            .any(|output| output.covenant_authorizing_input() == Some(peer_input_index))
        {
            anyhow::bail!("peer merge input must not authorize an output");
        }
    }
    let script_public_key =
        hex::decode(&output.script_public_key).context("decode merge output script public key")?;
    let actual_script_hash =
        p2sh_script_hash(&script_public_key).context("merge output is not P2SH")?;
    if actual_script_hash != *expected_script_hash {
        anyhow::bail!("merge output script hash does not match reconstructed state");
    }
    Ok(())
}

struct RevealClassification {
    template_name: String,
    args: Value,
    entrypoint: Option<String>,
    kind: &'static str,
}

fn is_kcc20_template(template_name: &str) -> bool {
    template_name.starts_with("KCC20")
}

fn classify_reveal(decoders: &DecoderRegistry, signature_script: &[u8], reveal: &[u8]) -> Option<RevealClassification> {
    classify_reveal_checked(decoders, signature_script, reveal).ok().flatten()
}

fn classify_reveal_checked(
    decoders: &DecoderRegistry,
    signature_script: &[u8],
    reveal: &[u8],
) -> Result<Option<RevealClassification>> {
    if let Some(decoder) = decoders.find_for_reveal(reveal) {
        let template_name = decoder.name().to_string();
        let mut args = Some(tn12_indexer_decoder::interpretation("constructor", decoder.decode_constructor(reveal))?);
        if template_name == "KCC20" {
            if let Some(action_args) = tn12_indexer_decoder::interpretation("kcc20_standard::decode_action_args_for_reveal", kcc20_standard::decode_action_args_for_reveal(signature_script, reveal))?
            {
                merge_json_object(&mut args, action_args);
            }
        }
        return Ok(Some(RevealClassification {
            template_name,
            args: args.unwrap_or(Value::Null),
            entrypoint: decoder.decode_action_checked(signature_script)?,
            kind: "covenant",
        }));
    }

    Ok(detect_inscription_from_reveal(reveal).map(|inscription| RevealClassification {
        template_name: inscription.template_name(),
        args: inscription.json,
        entrypoint: Some(inscription.op),
        kind: "inscription",
    }))
}

fn claim_matches_decoded_for_template(
    claimed: &claim::ClaimedDeployment,
    template_name: &str,
    decoded: &Value,
) -> bool {
    if template_name == "KCC20" {
        let claimed_args = claim::claimed_args_jsonb(claimed);
        let Ok(outputs) = kcc20_standard::deploy_output_states_from_claimed_args(&claimed_args)
        else {
            return false;
        };
        if decoded.get("standard").and_then(Value::as_str) != Some("KCC20") {
            return false;
        }
        let mint_policy = claimed_arg_text_any(claimed, &["mintPolicy"])
            .and_then(|value| value.parse::<u8>().ok());
        if mint_policy == Some(0) {
            let expected = outputs.first().and_then(|output| {
                output
                    .state
                    .get("extensionCommitment")
                    .and_then(Value::as_str)
            });
            let actual = decoded
                .get("state")
                .and_then(|state| state.get("extensionCommitment"))
                .or_else(|| decoded.get("extensionCommitment"))
                .and_then(Value::as_str);
            return expected.is_some() && expected == actual;
        }
        let expected_extension = outputs
            .first()
            .and_then(|output| output.state.get("extension"));
        let decoded_extension = decoded.get("extension");
        let Some((expected, actual)) = expected_extension.zip(decoded_extension) else {
            return false;
        };
        return [
            "kind",
            "creator",
            "ticker",
            "name",
            "displayScale",
            "maxSupply",
            "mintPolicy",
            "mintPriceSompi",
            "treasury",
            "protocolFeeRecipient",
            "protocolFeeBps",
            "holderExtensionCommitment",
        ]
        .iter()
        .all(|name| json_text_any(expected, &[*name]) == json_text_any(actual, &[*name]))
            && (claimed_arg_text_any(claimed, &["mintLaneCount"]).is_none()
                || json_text_any(expected, &["mintLaneCount"])
                    == json_text_any(actual, &["mintLaneCount"]));
    }

    if template_name == "KCC20Wrapper" {
        let claimed_canonical = claimed_arg_text_any(claimed, &["canonicalTokenId"])
            .map(|value| value.to_ascii_lowercase());
        let decoded_canonical =
            json_text_any(decoded, &["canonicalTokenId"]).map(|value| value.to_ascii_lowercase());
        return matches!(
            (claimed_canonical, decoded_canonical),
            (Some(claimed), Some(decoded))
                if claimed.len() == 64
                    && decoded.len() == 64
                    && claimed.chars().all(|c| c.is_ascii_hexdigit())
                    && decoded.chars().all(|c| c.is_ascii_hexdigit())
                    && claimed == decoded
        );
    }

    claim::matches_decoded(claimed, decoded)
}

fn claimed_arg_text_any(claimed: &claim::ClaimedDeployment, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        claimed
            .args
            .iter()
            .find(|arg| arg.name == *name)
            .and_then(|arg| json_text(&arg.value))
    })
}

/// Extract the *last* PUSHDATA in a script. For a P2SH covenant spend's
/// signature_script, that's the revealed redeem script (everything before
/// it is the entrypoint argument list). Exposed for the `reclassify`
/// subcommand which needs to re-run the decoder against historical spends.
pub fn extract_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = script;
    let mut last: Option<Vec<u8>> = None;
    while !cursor.is_empty() {
        match read_push(cursor) {
            Some((data, rest)) => {
                last = Some(data.to_vec());
                cursor = rest;
            }
            None => {
                cursor = &cursor[1..];
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::{
        assign_claimed_genesis_outputs, claim_matches_decoded_for_template, claimed_genesis_states,
        classify_reveal, extract_last_push, is_transient_persist_error,
        project_snapshot_start_kcc20, snapshot_controller_transition_successor,
        snapshot_start_payload_claim_matches, validate_merge_output_binding, PersistStats,
        TransientPersistError,
    };
    use crate::claim::{ClaimedArg, ClaimedDeployment};
    use serde_json::{json, Value};
    use tn12_indexer_core::RestTransaction;

    #[sqlx::test(migrations = "./migrations")]
    async fn wrapper_deploy_with_mistagged_wrap_payload_still_persists_deploy_state(
        pool: sqlx::PgPool,
    ) {
        use crate::{Persister, PgPersister};

        let mut deploy: RestTransaction = serde_json::from_str(include_str!(
            "../../../fixtures/tn10-wrapper-action/deploy.json"
        ))
        .unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&hex::decode(deploy.payload.as_deref().unwrap()).unwrap())
                .unwrap();
        payload["tn10"]["op"] = json!("wrap");
        deploy.payload = Some(hex::encode(payload.to_string()));

        let writer = PgPersister::new(pool.clone());
        writer.persist_tx(&deploy).await.unwrap();

        let deploy_txid = hex::decode(&deploy.transaction_id).unwrap();
        let root: serde_json::Value =
            sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1")
                .bind(&deploy_txid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(root["mode"], 1);
        assert_eq!(root["priceScale"], "1");

        let claim: (Option<String>, Option<serde_json::Value>, Option<String>) = sqlx::query_as(
            "SELECT claimed_template, claimed_args, claim_source \
             FROM covenants WHERE genesis_txid=$1 AND genesis_vout=0",
        )
        .bind(&deploy_txid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(claim.0.as_deref(), Some("KCC20Wrapper"));
        assert!(claim.1.is_some());
        assert_eq!(claim.2.as_deref(), Some("payload"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn captured_tn10_wrapper_action_keeps_controller_and_root_distinct(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};
        let deploy: RestTransaction = serde_json::from_str(include_str!(
            "../../../fixtures/tn10-wrapper-action/deploy.json"
        ))
        .unwrap();
        let wrap: RestTransaction = serde_json::from_str(include_str!(
            "../../../fixtures/tn10-wrapper-action/wrap.json"
        ))
        .unwrap();
        let writer = PgPersister::new(pool.clone());
        for _ in 0..2 {
            writer.persist_tx(&deploy).await.unwrap();
            writer.persist_tx(&wrap).await.unwrap();
        }
        let deploy_txid = hex::decode(&deploy.transaction_id).unwrap();
        let wrap_txid = hex::decode(&wrap.transaction_id).unwrap();
        let root: serde_json::Value =
            sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1")
                .bind(&deploy_txid)
                .fetch_one(&pool)
                .await
                .unwrap();
        let controller: serde_json::Value =
            sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1")
                .bind(&wrap_txid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(root["mode"], 1);
        assert_eq!(root["priceScale"], "1");
        assert!(controller.get("mode").is_none());
        assert_eq!(controller["priceScale"], "1");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1")
            .bind(&wrap_txid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(count > 0);
        let repair = writer
            .repair_wrapper_action_state(&wrap, false)
            .await
            .unwrap();
        assert!(!repair.changed);
        assert_eq!(repair.controller_vout, 1);
        sqlx::query("UPDATE covenant_utxos SET state=$1 WHERE txid=$2 AND vout=1")
            .bind(&root)
            .bind(&wrap_txid)
            .execute(&pool)
            .await
            .unwrap();
        assert!(writer.repair_wrapper_action_state(&wrap, false).await.unwrap().changed);
        assert!(writer.repair_wrapper_action_state(&wrap, true).await.unwrap().changed);
        assert!(!writer.repair_wrapper_action_state(&wrap, true).await.unwrap().changed);
        let repaired: serde_json::Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1",
        )
        .bind(&wrap_txid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(repaired, controller);
        sqlx::query("UPDATE covenant_utxos SET state=$1 WHERE txid=$2 AND vout=1")
            .bind(&root)
            .bind(&wrap_txid)
            .execute(&pool)
            .await
            .unwrap();
        let indexed_preview = writer
            .repair_wrapper_action_from_indexed_evidence(&wrap.transaction_id, false)
            .await
            .unwrap();
        assert!(indexed_preview.changed);
        assert!(!indexed_preview.applied);
        assert_eq!(indexed_preview.verified_state, controller);
        assert!(writer
            .repair_wrapper_action_from_indexed_evidence(&wrap.transaction_id, true)
            .await
            .unwrap()
            .changed);
        assert!(!writer
            .repair_wrapper_action_from_indexed_evidence(&wrap.transaction_id, true)
            .await
            .unwrap()
            .changed);
        let indexed_repaired: serde_json::Value =
            sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1")
                .bind(&wrap_txid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(indexed_repaired, controller);
        let mut wrong_address = wrap.clone();
        wrong_address.outputs[1].script_public_key_address =
            wrap.outputs[0].script_public_key_address.clone();
        assert!(writer
            .repair_wrapper_action_state(&wrong_address, false)
            .await
            .is_err());
        let mut missing_address = wrap.clone();
        missing_address.outputs[1].script_public_key_address = None;
        assert!(writer
            .repair_wrapper_action_state(&missing_address, false)
            .await
            .is_err());
        let mut rejected = wrap.clone();
        rejected.is_accepted = false;
        assert!(writer
            .repair_wrapper_action_state(&rejected, false)
            .await
            .is_err());
        let preserved_root: serde_json::Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1",
        )
        .bind(&deploy_txid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(preserved_root, root);
        let count_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE txid=$1",
        )
        .bind(&wrap_txid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count_after, count);
        sqlx::query(
            "UPDATE covenants SET address='mismatched' WHERE covenant_id=(SELECT covenant_id \
             FROM covenant_utxos WHERE txid=$1 AND vout=1)",
        )
        .bind(&wrap_txid)
        .execute(&pool)
        .await
        .unwrap();
        assert!(writer
            .repair_wrapper_action_from_indexed_evidence(&wrap.transaction_id, true)
            .await
            .is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn claimed_genesis_repair_fills_only_missing_states(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};

        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-ten-lane-deploy.json"
        ))
        .unwrap();
        let writer = PgPersister::new(pool.clone());
        writer.persist_tx(&tx).await.unwrap();
        let txid = hex::decode(&tx.transaction_id).unwrap();
        sqlx::query("UPDATE covenant_utxos SET state=NULL WHERE txid=$1 AND vout BETWEEN 1 AND 9")
            .bind(&txid)
            .execute(&pool)
            .await
            .unwrap();

        let mut rejected = tx.clone();
        rejected.is_accepted = false;
        assert!(writer.repair_claimed_genesis_states(&rejected, true).await.is_err());
        let mut incomplete = tx.clone();
        incomplete.outputs.remove(9);
        assert!(writer.repair_claimed_genesis_states(&incomplete, true).await.is_err());

        let preview = writer.repair_claimed_genesis_states(&tx, false).await.unwrap();
        assert_eq!(preview.null_states_found, 9);
        assert_eq!(preview.states_repaired, 0);
        let applied = writer.repair_claimed_genesis_states(&tx, true).await.unwrap();
        assert_eq!(applied.states_repaired, 9);
        assert_eq!(writer.repair_claimed_genesis_states(&tx, true).await.unwrap().states_repaired, 0);
        let missing: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND state IS NULL")
            .bind(&txid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(missing, 0);

        sqlx::query("UPDATE covenant_utxos SET state=NULL WHERE txid=$1 AND vout BETWEEN 1 AND 9")
            .bind(&txid).execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM covenant_utxos WHERE txid=$1 AND vout=10")
            .bind(&txid).execute(&pool).await.unwrap();
        assert!(writer.repair_claimed_genesis_states(&tx, true).await.is_err());
        let still_missing: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND vout BETWEEN 1 AND 9 AND state IS NULL"
        ).bind(&txid).fetch_one(&pool).await.unwrap();
        assert_eq!(still_missing, 9, "a missing later output must roll back earlier repairs");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn claimed_genesis_state_replay_recovers_after_reorg(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};

        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-ten-lane-deploy.json"
        )).unwrap();
        let writer = PgPersister::new(pool.clone());
        let txid = hex::decode(&tx.transaction_id).unwrap();
        writer.persist_tx(&tx).await.unwrap();
        let accepting_hash = hex::decode(tx.accepting_block_hash.as_deref().unwrap()).unwrap();
        writer.revert_block(&accepting_hash).await.unwrap();
        let after_reorg: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE txid=$1")
            .bind(&txid).fetch_one(&pool).await.unwrap();
        assert_eq!(after_reorg, 0);
        assert!(writer.repair_claimed_genesis_states(&tx, true).await.is_err());

        writer.persist_tx(&tx).await.unwrap();
        let restored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND state IS NOT NULL"
        ).bind(&txid).fetch_one(&pool).await.unwrap();
        assert_eq!(restored, 11);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fee_ticket_root_repair_requires_matching_stored_genesis(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};

        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket-root-deploy.json"
        )).unwrap();
        let writer = PgPersister::new(pool.clone());
        writer.persist_tx(&tx).await.unwrap();
        let txid = hex::decode(&tx.transaction_id).unwrap();
        sqlx::query("UPDATE covenant_utxos SET state=NULL WHERE txid=$1 AND vout=0")
            .bind(&txid).execute(&pool).await.unwrap();
        let preview = writer.repair_claimed_genesis_states(&tx, false).await.unwrap();
        assert_eq!(preview.outputs_verified, 1);
        assert_eq!(preview.null_states_found, 1);
        assert_eq!(writer.repair_claimed_genesis_states(&tx, true).await.unwrap().states_repaired, 1);
        let state: serde_json::Value = sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(&txid).fetch_one(&pool).await.unwrap();
        assert_eq!(state["stateMode"], 1);
        assert_eq!(state["denomination"], "550");
        assert_eq!(writer.repair_claimed_genesis_states(&tx, true).await.unwrap().states_repaired, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fee_ticket_genesis_is_verified_without_first_spend_and_repairs_replay(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket-root-deploy-20261107.json"
        )).unwrap();
        let writer = PgPersister::new(pool.clone());
        writer.persist_tx(&tx).await.unwrap();
        let root = hex::decode("eb27bbef1b9946b517b785de2143701458cfc4ed8d21529d52b95c04759afcdc").unwrap();
        for replay in 0..3 {
            if replay == 1 {
                // Simulate the existing deployment persisted before this fix.
                sqlx::query("UPDATE covenants SET template_name=NULL,constructor_args=NULL,claim_verified=FALSE,claim_verified_at_ms=NULL,classification_kind='unknown',classification_status='unrevealed' WHERE covenant_id=$1")
                    .bind(&root).execute(&pool).await.unwrap();
            }
            writer.persist_tx(&tx).await.unwrap();
            let row: (String, bool, String, serde_json::Value) = sqlx::query_as(
                "SELECT template_name,claim_verified,classification_status,constructor_args FROM covenants WHERE covenant_id=$1")
                .bind(&root).fetch_one(&pool).await.unwrap();
            assert_eq!(row.0, "KCC20FeeTicket");
            assert!(row.1);
            assert_eq!(row.2, "matched");
            assert_eq!(row.3["denomination"], "2000000000");
            assert_eq!(row.3["utilityTokenId"], "dd59166f8db75fdbf92443deee51e4f6e6644626f3d051bb3bf429db82d0b65e");
        }
        let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
            .bind(&root).fetch_one(&pool).await.unwrap();
        assert_eq!(actions, 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fee_ticket_genesis_does_not_verify_a_mismatched_output(pool: sqlx::PgPool) {
        use crate::{Persister, PgPersister};
        let mut tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket-root-deploy-20261107.json"
        )).unwrap();
        tx.outputs[0].script_public_key = format!("aa20{}87", "ab".repeat(32));
        PgPersister::new(pool.clone()).persist_tx(&tx).await.unwrap();
        let verified: i64 = sqlx::query_scalar("SELECT count(*) FROM covenants WHERE claim_verified=TRUE")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(verified, 0);
    }

    #[test]
    fn accepted_tn10_ten_lane_deploy_opens_every_genesis_output() {
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-ten-lane-deploy.json"
        ))
        .unwrap();
        let claim = tx.payload.as_deref().and_then(crate::claim::parse_payload_envelope).unwrap();
        let (covenant_id, states) = claimed_genesis_states(&tx, &claim).unwrap().unwrap();
        assert_eq!(hex::encode(covenant_id), "42cddfbdd2eb3a787af34c8c2de1c208da0e5d9483df6da270befaddfac5c920");
        assert_eq!(states.len(), 11);
        assert_eq!(states.iter().map(|(vout, _)| *vout).collect::<Vec<_>>(), (0..11).collect::<Vec<_>>());
    }

    #[test]
    fn deploy_with_nonzero_authorizing_input_uses_that_input_for_covenant_id() {
        let mut tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-ten-lane-deploy.json"
        )).unwrap();
        let mut funding = tx.inputs[0].clone();
        funding.previous_outpoint_hash = "33".repeat(32);
        tx.inputs.insert(0, funding);
        let indexes = (0..11).collect::<Vec<_>>();
        let expected = tn12_indexer_core::compute_genesis_covenant_id_for_outputs_at_input(
            &tx, 1, &indexes
        ).unwrap();
        for output in &mut tx.outputs[..11] {
            output.covenant_id = Some(expected.clone());
            output.covenant.as_mut().unwrap().covenant_id = Some(expected.clone());
            output.covenant.as_mut().unwrap().authorizing_input = Some(1);
        }
        let claim = tx.payload.as_deref().and_then(crate::claim::parse_payload_envelope).unwrap();
        let (actual, states) = claimed_genesis_states(&tx, &claim).unwrap().unwrap();
        assert_eq!(hex::encode(actual), expected);
        assert_eq!(states.len(), 11);
    }

    #[test]
    fn accepted_tn10_fee_ticket_root_opens_only_matching_output() {
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket-root-deploy.json"
        ))
        .unwrap();
        let claim = tx.payload.as_deref().and_then(crate::claim::parse_payload_envelope).unwrap();
        let (covenant_id, states) = claimed_genesis_states(&tx, &claim).unwrap().unwrap();
        assert_eq!(hex::encode(covenant_id), "326a8177a24d488d02c351eaef506c81976b27091e27d0fb5cee4ee9b15864c6");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].0, 0);
        assert_eq!(states[0].1["stateMode"], 1);
    }

    #[test]
    fn equal_hash_deploy_lanes_consume_distinct_vouts() {
        let hash = [0x51_u8; 32];
        let outputs = (0..10)
            .map(|index| json!({
                "index": index,
                "amount": 100_000_000,
                "script_public_key": format!("aa20{}87", hex::encode(hash)),
            }))
            .collect::<Vec<_>>();
        let tx: RestTransaction = serde_json::from_value(json!({
            "transaction_id": "11".repeat(32),
            "outputs": outputs,
        }))
        .unwrap();
        let expected = (0..10).map(|index| (hash, json!({"lane": index}))).collect();
        let assigned = assign_claimed_genesis_outputs(&tx, expected).unwrap();
        assert_eq!(assigned.iter().map(|(output, _)| output.index).collect::<Vec<_>>(), (0..10).collect::<Vec<_>>());
        assert_eq!(assigned[9].1["lane"], 9);

        assert!(assign_claimed_genesis_outputs(&tx, vec![(hash, json!({}))]).is_err());
        let eleven = (0..11).map(|_| (hash, json!({}))).collect();
        assert!(assign_claimed_genesis_outputs(&tx, eleven).is_err());
        let mut duplicate_vout = tx.clone();
        duplicate_vout.outputs[9].index = 8;
        let ten = (0..10).map(|_| (hash, json!({}))).collect();
        assert!(assign_claimed_genesis_outputs(&duplicate_vout, ten).is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn settled_replay_restores_earliest_genesis_and_action_labels(pool: sqlx::PgPool) {
        let early_block = vec![0xaa_u8; 32];
        let late_block = vec![0xbb_u8; 32];
        let early_txid = vec![0x11_u8; 32];
        let late_txid = vec![0x22_u8; 32];
        let covenant_id = vec![0x33_u8; 32];
        let script_hash = vec![0x55_u8; 32];
        for (hash, score, time) in [
            (&early_block, 100_i64, 1_000_i64),
            (&late_block, 200, 2_000),
        ] {
            sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,$2,0,ARRAY[]::bytea[],$3,true,$3)")
                .bind(hash).bind(score).bind(time).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES($1,'test',0,$4,$2,0,$3,2000)")
            .bind(&covenant_id).bind(&late_txid).bind(&late_block).bind(&script_hash)
            .execute(&pool).await.unwrap();
        for (txid, block) in [(&early_txid, &early_block), (&late_txid, &late_block)] {
            sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status) VALUES($1,0,$2,'test',1,decode('aa20','hex'),$3,'active')")
                .bind(txid).bind(&covenant_id).bind(block)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action) VALUES($1,$2,$3,1000,'continuation'),($1,$4,$5,2000,'deploy')")
            .bind(&covenant_id).bind(&early_txid).bind(&early_block)
            .bind(&late_txid).bind(&late_block).execute(&pool).await.unwrap();
        let writer = super::PgPersister::new(pool.clone());
        assert_eq!(
            writer.normalize_replayed_genesis(100, 100).await.unwrap(),
            (1, 2)
        );
        let genesis: Vec<u8> =
            sqlx::query_scalar("SELECT genesis_txid FROM covenants WHERE covenant_id=$1")
                .bind(&covenant_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(genesis, early_txid);
        let labels: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM covenant_actions WHERE covenant_id=$1 ORDER BY block_time_ms",
        )
        .bind(&covenant_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(labels, vec!["deploy", "continuation"]);
        assert_eq!(
            writer.normalize_replayed_genesis(100, 100).await.unwrap(),
            (0, 0)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn settled_replay_deduplicates_old_deploy_outpoint(pool: sqlx::PgPool) {
        let early_block = vec![0xaa_u8; 32];
        let late_block = vec![0xbb_u8; 32];
        let early_txid = vec![0x11_u8; 32];
        let late_txid = vec![0x22_u8; 32];
        let covenant_id = vec![0x33_u8; 32];
        let script_hash = vec![0x55_u8; 32];
        for (hash, score, time) in [
            (&early_block, 100_i64, 1_000_i64),
            (&late_block, 200, 2_000),
        ] {
            sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,$2,0,ARRAY[]::bytea[],$3,true,$3)")
                .bind(hash).bind(score).bind(time).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES($1,'test',0,$4,$2,0,$3,2000)")
            .bind(&covenant_id).bind(&late_txid).bind(&late_block).bind(&script_hash)
            .execute(&pool).await.unwrap();
        for (txid, block) in [(&early_txid, &early_block), (&late_txid, &late_block)] {
            sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status) VALUES($1,0,$2,'test',1,decode('aa20','hex'),$3,'active')")
                .bind(txid).bind(&covenant_id).bind(block)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) VALUES($1,$2,$3,1000,'continuation','{\"vout\":0}'),($1,$4,$5,2000,'deploy','{\"vout\":0}'),($1,$4,$5,2000,'continuation','{\"vout\":0,\"state\":\"different\"}')")
            .bind(&covenant_id).bind(&early_txid).bind(&early_block)
            .bind(&late_txid).bind(&late_block).execute(&pool).await.unwrap();
        let writer = super::PgPersister::new(pool.clone());
        assert!(writer.normalize_replayed_genesis(100, 100).await.is_err());
        let genesis: Vec<u8> =
            sqlx::query_scalar("SELECT genesis_txid FROM covenants WHERE covenant_id=$1")
                .bind(&covenant_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(genesis, late_txid);
        sqlx::query("UPDATE covenant_actions SET outputs='{\"vout\":0}' WHERE covenant_id=$1 AND txid=$2 AND action='continuation'")
            .bind(&covenant_id).bind(&late_txid).execute(&pool).await.unwrap();
        assert_eq!(
            writer.normalize_replayed_genesis(100, 100).await.unwrap(),
            (1, 2)
        );
        let labels: Vec<(Vec<u8>, String)> = sqlx::query_as(
            "SELECT txid, action FROM covenant_actions WHERE covenant_id=$1 ORDER BY block_time_ms, id",
        )
        .bind(&covenant_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            labels,
            vec![
                (early_txid, "deploy".into()),
                (late_txid, "continuation".into())
            ]
        );
        assert_eq!(
            writer.normalize_replayed_genesis(100, 100).await.unwrap(),
            (0, 0)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn settled_replay_keeps_unclassified_shared_script_actions(pool: sqlx::PgPool) {
        let early_block = vec![0xaa_u8; 32];
        let late_block = vec![0xbb_u8; 32];
        let early_txid = vec![0x11_u8; 32];
        let late_txid = vec![0x22_u8; 32];
        let other_deploy_txid = vec![0x44_u8; 32];
        let covenant_id = vec![0x33_u8; 32];
        let script_hash = vec![0x66_u8; 32];
        for (hash, score, time) in [
            (&early_block, 100_i64, 1_000_i64),
            (&late_block, 200, 2_000),
        ] {
            sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,$2,0,ARRAY[]::bytea[],$3,true,$3)")
                .bind(hash).bind(score).bind(time).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES($1,'test',0,$4,$2,0,$3,2000)")
            .bind(&covenant_id).bind(&late_txid).bind(&late_block).bind(&script_hash)
            .execute(&pool).await.unwrap();
        for (txid, block) in [(&early_txid, &early_block), (&late_txid, &late_block)] {
            sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status) VALUES($1,0,$2,'test',1,decode('aa20','hex'),$3,'active')")
                .bind(txid).bind(&covenant_id).bind(block)
                .execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) VALUES($1,$2,$3,1000,'continuation','{\"vout\":0}'),($1,$4,$5,2000,'deploy','{\"vout\":0}'),($1,$4,$5,2000,'continuation','{\"vout\":0}'),($1,$6,$5,2000,'deploy','{\"vout\":0}')")
            .bind(&covenant_id).bind(&early_txid).bind(&early_block)
            .bind(&late_txid).bind(&late_block).bind(&other_deploy_txid)
            .execute(&pool).await.unwrap();
        let writer = super::PgPersister::new(pool.clone());
        assert_eq!(
            writer.normalize_replayed_genesis(100, 100).await.unwrap(),
            (1, 0)
        );
        let genesis: Vec<u8> =
            sqlx::query_scalar("SELECT genesis_txid FROM covenants WHERE covenant_id=$1")
                .bind(&covenant_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(genesis, early_txid);
        let labels: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 ORDER BY action",
        )
        .bind(&covenant_id)
        .bind(&late_txid)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(labels, vec!["continuation", "deploy"]);
    }

    #[test]
    fn budgeted_writer_rejects_invalid_and_legacy_settings() {
        for value in ["0", "15", "65", "128", "not-a-number"] {
            assert!(super::budgeted_batch_size(&|name| {
                (name == "TN12_BUDGETED_GENERIC_BULK_MAX_TXS").then(|| value.to_owned())
            })
            .is_err());
        }
        assert!(super::budgeted_batch_size(&|name| {
            (name == "TN12_GENERIC_BULK_MAX_TXS").then(|| "128".into())
        })
        .unwrap_err()
        .to_string()
        .contains("unsupported"));
        for expected in [16, 32, 64] {
            assert_eq!(
                super::budgeted_batch_size(&|name| {
                    (name == "TN12_BUDGETED_GENERIC_BULK_MAX_TXS").then(|| expected.to_string())
                })
                .unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn wrpc_bulk_requires_own_explicit_flag_and_preserves_guards() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for value in [None, Some("0"), Some("true"), Some(""), Some("1")] {
            let writer =
                super::PgPersister::for_wrpc_settings(pool.clone(), "testnet-10", |name| {
                    if name == "TN12_WRPC_GENERIC_BULK_PERSIST" {
                        value.map(str::to_owned)
                    } else {
                        None
                    }
                })
                .unwrap();
            assert_eq!(writer.network_id, "testnet-10");
            assert!(writer.wait_for_writer_lock);
            assert_eq!(writer.generic_bulk_max_txs, Some(16));
            assert_eq!(writer.generic_bulk_persist, value == Some("1"));
            assert_eq!(writer.generic_writer_budget, value == Some("1"));
            assert_eq!(
                writer.historical_acceptance_hold_budget,
                std::time::Duration::from_millis(350)
            );
            assert_eq!(
                writer
                    .with_startup_recovery_acceptance_budget()
                    .historical_acceptance_hold_budget,
                std::time::Duration::from_secs(5)
            );
        }
    }

    #[tokio::test]
    async fn tip_writer_budget_requires_explicit_bulk_and_budget_settings() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for (bulk, budget, enabled) in [
            (None, None, false),
            (Some("1"), None, false),
            (None, Some("1"), false),
            (Some("0"), Some("1"), false),
            (Some("1"), Some("0"), false),
            (Some("1"), Some("true"), false),
            (Some("1"), Some("1"), true),
        ] {
            let writer =
                super::PgPersister::for_tip_follow_settings(pool.clone(), |name| match name {
                    "TN12_GENERIC_BULK_PERSIST" => bulk.map(str::to_owned),
                    "TN12_GENERIC_WRITER_BUDGET" => budget.map(str::to_owned),
                    "TN12_BUDGETED_GENERIC_BULK_MAX_TXS" | "TN12_GENERIC_BULK_MAX_TXS" => None,
                    "TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS" | "TN12_HISTORY_READ_PREFETCH" => None,
            "TN12_WRITER_LIVE_PRIORITY" => None,
                    _ => panic!("unexpected configuration key {name}"),
                })
                .unwrap();
            assert_eq!(writer.generic_writer_budget, enabled);
            assert_eq!(
                writer.generic_bulk_max_txs,
                enabled.then_some(16),
                "guarded TIP pilot must ignore the normal default batch size"
            );
            assert_eq!(writer.generic_bulk_persist, bulk == Some("1"));
            assert!(writer.wait_for_writer_lock);
            assert_eq!(
                writer.historical_acceptance_hold_budget,
                std::time::Duration::from_millis(350)
            );
        }
        let live = super::PgPersister::new(pool.clone());
        assert!(!live.generic_writer_budget && !live.generic_bulk_persist);
        let custom = super::PgPersister::with_decoders(pool, super::default_registry());
        assert!(!custom.generic_writer_budget);
    }

    #[tokio::test]
    async fn budgeted_tip_batch_cap_is_explicit_and_bounded() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for (setting, expected) in [(None, 16), (Some("32"), 32), (Some("64"), 64)] {
            let writer =
                super::PgPersister::for_tip_follow_settings(pool.clone(), |name| match name {
                    "TN12_GENERIC_BULK_PERSIST" | "TN12_GENERIC_WRITER_BUDGET" => {
                        Some("1".to_string())
                    }
                    "TN12_BUDGETED_GENERIC_BULK_MAX_TXS" => setting.map(str::to_owned),
                    "TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS"
                    | "TN12_GENERIC_BULK_MAX_TXS"
                    | "TN12_HISTORY_READ_PREFETCH" => None,
                    "TN12_WRITER_LIVE_PRIORITY" => None,
                    _ => panic!("unexpected configuration key {name}"),
                })
                .unwrap();
            assert!(writer.generic_writer_budget);
            assert_eq!(writer.generic_bulk_max_txs, Some(expected));
        }
        let writer = super::PgPersister::for_tip_follow_settings(pool, |name| match name {
            "TN12_GENERIC_BULK_PERSIST" => Some("1".to_string()),
            "TN12_GENERIC_WRITER_BUDGET" => None,
            "TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS" | "TN12_HISTORY_READ_PREFETCH" => None,
            "TN12_WRITER_LIVE_PRIORITY" => None,
            "TN12_BUDGETED_GENERIC_BULK_MAX_TXS" => {
                panic!("the budgeted cap must be ignored when budget mode is off")
            }
            _ => panic!("unexpected configuration key {name}"),
        })
        .unwrap();
        assert!(!writer.generic_writer_budget);
        assert_eq!(writer.generic_bulk_max_txs, None);
    }

    #[tokio::test]
    async fn isolated_history_acceptance_budget_is_bounded_and_opt_in() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for (value, expected_ms) in [
            (None, 350),
            (Some("invalid"), 350),
            (Some("0"), 0),
            (Some("1"), 350),
            (Some("5000"), 5000),
            (Some("60000"), 5000),
        ] {
            let writer = super::PgPersister::for_tip_follow_settings(pool.clone(), |name| {
                if name == "TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS" {
                    value.map(str::to_owned)
                } else {
                    None
                }
            })
            .unwrap();
            assert_eq!(
                writer.historical_acceptance_hold_budget,
                std::time::Duration::from_millis(expected_ms)
            );
        }
    }

    #[test]
    fn dependency_order_handles_reverse_chains_and_rejects_invalid_graphs() {
        use super::transactions_in_dependency_order;
        use tn12_indexer_core::RestTxInput;
        let tx = |id: &str, parents: &[&str]| RestTransaction {
            transaction_id: id.into(),
            inputs: parents
                .iter()
                .map(|parent| RestTxInput {
                    previous_outpoint_hash: (*parent).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let txs = vec![
            tx("cc", &["BB", "bb"]),
            tx("aa", &[]),
            tx("bb", &["aa"]),
            tx("dd", &[]),
        ];
        let ordered = transactions_in_dependency_order(&txs).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|tx| tx.transaction_id.as_str())
                .collect::<Vec<_>>(),
            vec!["aa", "bb", "cc", "dd"]
        );
        assert!(matches!(
            transactions_in_dependency_order(&ordered).unwrap(),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(transactions_in_dependency_order(&[tx("aa", &[]), tx("AA", &[])]).is_err());
        assert!(transactions_in_dependency_order(&[tx("aa", &["bb"]), tx("bb", &["aa"])]).is_err());
        assert!(transactions_in_dependency_order(&[tx("aa", &["aa"])]).is_err());
        assert!(transactions_in_dependency_order(&[tx("aa", &["external"])]).is_ok());
    }

    #[test]
    fn standard_kcc20_classification_includes_authenticated_action_extension() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../tn12-indexer-decoder/fixtures/kcc20/KCC20.placeholder.json"
        ))
        .unwrap();
        let reveal = artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect::<Vec<_>>();
        let mut signature_script = Vec::new();
        push_test_int(&mut signature_script, 1);
        push_test_data(&mut signature_script, &[0x11; 32]);
        push_test_data(&mut signature_script, &test_ascii32("TEST"));
        push_test_data(&mut signature_script, &test_ascii32("Test Token"));
        push_test_int(&mut signature_script, 100);
        push_test_int(&mut signature_script, 1000);
        push_test_int(&mut signature_script, 2);
        push_test_int(&mut signature_script, 0);
        push_test_int(&mut signature_script, 0);
        push_test_data(&mut signature_script, &[0x22; 32]);
        push_test_data(&mut signature_script, &[0x33; 32]);
        push_test_int(&mut signature_script, 200);
        push_test_int(&mut signature_script, 1000);
        push_test_int(&mut signature_script, 0);
        push_test_data(&mut signature_script, &[0x44; 32]);
        push_test_data(&mut signature_script, &[0x55; 64]);
        push_test_int(&mut signature_script, 1);
        push_test_int(&mut signature_script, 0);
        push_test_data(
            &mut signature_script,
            &tn12_indexer_decoder::kcc20_standard::SET_PUBLIC_MINT_ACTIVE_TAG,
        );
        push_test_data(&mut signature_script, &reveal);

        let classification = classify_reveal(
            &tn12_indexer_decoder::default_registry(),
            &signature_script,
            &reveal,
        )
        .unwrap();

        assert_eq!(classification.template_name, "KCC20");
        assert_eq!(classification.args["standard"], "KCC20");
        assert_eq!(classification.args["extension"]["ticker"], "TEST");
        assert_eq!(classification.args["active"], true);
    }

    #[test]
    fn malformed_standard_kcc20_action_requires_deferred_interpretation() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../tn12-indexer-decoder/fixtures/kcc20/KCC20.placeholder.json"
        ))
        .unwrap();
        let reveal = artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect::<Vec<_>>();
        let mut signature_script = Vec::new();
        push_test_data(
            &mut signature_script,
            &tn12_indexer_decoder::kcc20_standard::MINT_PUBLIC_TAG,
        );
        push_test_data(&mut signature_script, &reveal);

        let result = super::classify_reveal_checked(
            &tn12_indexer_decoder::default_registry(),
            &signature_script,
            &reveal,
        );
        let Err(error) = result else { panic!("malformed action must be retained"); };
        assert!(error.downcast_ref::<tn12_indexer_decoder::InterpretationFailure>().is_some());
    }

    fn test_ascii32(value: &str) -> [u8; 32] {
        let mut output = [0u8; 32];
        output[..value.len()].copy_from_slice(value.as_bytes());
        output
    }

    fn push_test_int(script: &mut Vec<u8>, value: i64) {
        match value {
            0 => script.push(0x00),
            1..=16 => script.push(0x50 + value as u8),
            _ => {
                let mut bytes = value.to_le_bytes().to_vec();
                while bytes.len() > 1 && bytes.last() == Some(&0) {
                    bytes.pop();
                }
                push_test_data(script, &bytes);
            }
        }
    }

    fn push_test_data(script: &mut Vec<u8>, data: &[u8]) {
        if data.len() <= 75 {
            script.push(data.len() as u8);
        } else if data.len() <= u8::MAX as usize {
            script.extend_from_slice(&[0x4c, data.len() as u8]);
        } else {
            script.push(0x4d);
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        script.extend_from_slice(data);
    }

    #[test]
    fn merge_projection_requires_exact_native_output_binding() {
        let covenant_id = vec![0x41; 32];
        let p2sh = format!("aa20{}87", "11".repeat(32));
        let tx_json = json!({
            "transaction_id": "22".repeat(32),
            "outputs": [{
                "index": 0,
                "amount": 50_000_000,
                "script_public_key": p2sh,
                "covenant_id": hex::encode(&covenant_id),
                "covenant_authorizing_input": 1
            }]
        });
        let tx: RestTransaction = serde_json::from_value(tx_json.clone()).unwrap();
        let expected_script_hash = [0x11; 32];
        assert!(validate_merge_output_binding(
            &tx,
            0,
            1,
            &[2],
            &covenant_id,
            &expected_script_hash
        )
        .is_ok());

        let mut wrong_id = tx_json.clone();
        wrong_id["outputs"][0]["covenant_id"] = json!("42".repeat(32));
        let wrong_id: RestTransaction = serde_json::from_value(wrong_id).unwrap();
        assert!(validate_merge_output_binding(
            &wrong_id,
            0,
            1,
            &[2],
            &covenant_id,
            &expected_script_hash
        )
        .is_err());

        let mut wrong_input = tx_json.clone();
        wrong_input["outputs"][0]["covenant_authorizing_input"] = json!(0);
        let wrong_input: RestTransaction = serde_json::from_value(wrong_input).unwrap();
        assert!(validate_merge_output_binding(
            &wrong_input,
            0,
            1,
            &[2],
            &covenant_id,
            &expected_script_hash
        )
        .is_err());

        let wrong_script_hash = [0x12; 32];
        assert!(
            validate_merge_output_binding(&tx, 0, 1, &[2], &covenant_id, &wrong_script_hash)
                .is_err()
        );

        let mut extra_primary_output = tx_json.clone();
        extra_primary_output["outputs"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "index": 1,
                "amount": 50_000_000,
                "script_public_key": format!("aa20{}87", "13".repeat(32)),
                "covenant_id": hex::encode(&covenant_id),
                "covenant_authorizing_input": 1
            }));
        let extra_primary_output: RestTransaction =
            serde_json::from_value(extra_primary_output).unwrap();
        assert!(validate_merge_output_binding(
            &extra_primary_output,
            0,
            1,
            &[2],
            &covenant_id,
            &expected_script_hash
        )
        .is_err());

        let mut peer_output = tx_json;
        peer_output["outputs"].as_array_mut().unwrap().push(json!({
            "index": 1,
            "amount": 50_000_000,
            "script_public_key": format!("aa20{}87", "14".repeat(32)),
            "covenant_id": hex::encode(&covenant_id),
            "covenant_authorizing_input": 2
        }));
        let peer_output: RestTransaction = serde_json::from_value(peer_output).unwrap();
        assert!(validate_merge_output_binding(
            &peer_output,
            0,
            1,
            &[2],
            &covenant_id,
            &expected_script_hash
        )
        .is_err());
    }

    #[test]
    fn snapshot_start_projects_with_its_authenticated_historical_template() {
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../tests/fixtures/snapshot-start-tn10/start.json"
        ))
        .unwrap();
        let signature_script = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let reveal = extract_last_push(&signature_script).unwrap();
        let registry = tn12_indexer_decoder::default_registry();
        assert_eq!(
            registry
                .find_for_reveal(&reveal)
                .map(|decoder| decoder.name()),
            Some("KCC20SnapshotBootstrap")
        );
        let controller_signature_script = hex::decode(&tx.inputs[1].signature_script).unwrap();
        let controller_reveal = extract_last_push(&controller_signature_script).unwrap();
        assert_eq!(
            registry
                .find_for_reveal(&controller_reveal)
                .map(|decoder| decoder.name()),
            Some("KCC20SnapshotController")
        );
        let controller_start =
            tn12_indexer_decoder::kcc20_snapshot_controller::decode_claim_transition(
                &controller_signature_script,
                &controller_reveal,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            controller_start["projectionSchema"],
            "kcc20-snapshot-controller-start/v2"
        );
        let controller_id = tx.outputs[1]
            .canonical_covenant_id()
            .and_then(|id| hex::decode(id).ok())
            .unwrap();
        let (controller_output_index, controller_state) =
            snapshot_controller_transition_successor(&tx, 1, &controller_id, &controller_start)
                .unwrap()
                .unwrap();
        assert_eq!(controller_output_index, 1);
        assert_eq!(
            controller_state["tokenId"],
            "584b5120436111b6a77cf4e81c1cfaf310068613b9e031199c5bbbb824621a62"
        );
        let original: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/snapshot-start-tn10/start.json"
        ))
        .unwrap();
        for case in ["missing", "duplicate", "extra", "wrong_authorizer"] {
            let mut value = original.clone();
            match case {
                "missing" => {
                    value["outputs"].as_array_mut().unwrap().remove(1);
                }
                "duplicate" | "extra" => {
                    let mut output = value["outputs"][1].clone();
                    output["index"] = json!(3);
                    if case == "extra" {
                        output["covenant_id"] = json!("ff".repeat(32));
                    }
                    value["outputs"].as_array_mut().unwrap().push(output);
                }
                "wrong_authorizer" => {
                    value["outputs"][1]["covenant_authorizing_input"] = json!(0);
                }
                _ => unreachable!(),
            }
            let invalid: RestTransaction = serde_json::from_value(value).unwrap();
            assert!(
                snapshot_controller_transition_successor(
                    &invalid,
                    1,
                    &controller_id,
                    &controller_start,
                )
                .is_err(),
                "accepted {case} controller successor"
            );
        }
        let start = tn12_indexer_decoder::kcc20_snapshot_bootstrap::decode_bootstrap_action(
            &signature_script,
            &reveal,
        )
        .unwrap()
        .unwrap();
        let (mut template_prefix, template_suffix) =
            tn12_indexer_decoder::kcc20_snapshot_bootstrap::decode_bootstrap_kcc20_template_parts(
                &signature_script,
                &reveal,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            start["kcc20TemplateHash"],
            "911f0638ccb7368bf36d117f1725073ae7ee487ce8b58ca3e8375051c2d40f6c"
        );
        assert_eq!(
            start["projectionSchema"],
            "kcc20-snapshot-bootstrap-start/v2"
        );
        let projected =
            project_snapshot_start_kcc20(&tx, &start, None, &template_prefix, &template_suffix)
                .unwrap();
        assert_eq!(projected.output_states.len(), 1);
        // The decoder schema above belongs to the bootstrap input's `spend`
        // action. Persistence writes this separate marker onto the derived
        // KCC20 `deploy` action; the snapshot-genesis repair migration is
        // deliberately bound to this deploy marker.
        assert_eq!(
            projected.action_args["projectionSchema"],
            "kcc20-snapshot-token-genesis/v1"
        );
        let mut wrong_genesis = original;
        wrong_genesis["outputs"][0]["covenant_id"] = json!("ff".repeat(32));
        let wrong_genesis: RestTransaction = serde_json::from_value(wrong_genesis).unwrap();
        assert!(project_snapshot_start_kcc20(
            &wrong_genesis,
            &start,
            None,
            &template_prefix,
            &template_suffix,
        )
        .is_err());
        template_prefix[0] ^= 1;
        let error =
            project_snapshot_start_kcc20(&tx, &start, None, &template_prefix, &template_suffix)
                .err()
                .unwrap();
        assert!(error.to_string().contains("committed hash"));
    }

    #[test]
    fn snapshot_start_projects_only_the_exact_kip20_reserve_family() {
        let reserve = json!({
            "amount": "1000",
            "owner": "33".repeat(32),
            "ownerScheme": 4,
            "borrowScheme": 0,
            "borrowGuard": "00".repeat(32),
            "extensionCommitment": "44".repeat(32)
        });
        let reserve_script =
            tn12_indexer_decoder::kcc20_standard::script_for_state_value(&reserve).unwrap();
        let template_prefix =
            &reserve_script[..tn12_indexer_decoder::kcc20_standard::KCC20_STATE_START];
        let template_suffix = &reserve_script
            [tn12_indexer_decoder::kcc20_standard::KCC20_STATE_START
                + tn12_indexer_decoder::kcc20_standard::KCC20_STATE_LEN..];
        let template_hash = tn12_indexer_decoder::token_profiles::template_hash(
            &reserve_script,
            template_prefix.len(),
        )
        .unwrap();
        let reserve_script_hash = tn12_indexer_core::blake2b_256(&reserve_script);
        let mut tx_json = json!({
            "transaction_id": "55".repeat(32),
            "version": 1,
            "inputs": [
                {
                    "previous_outpoint_hash": "66".repeat(32),
                    "previous_outpoint_index": "0"
                },
                {
                    "previous_outpoint_hash": "77".repeat(32),
                    "previous_outpoint_index": "2"
                }
            ],
            "outputs": [{
                "index": 0,
                "amount": 50_000_000,
                "script_public_key": format!("aa20{}87", hex::encode(reserve_script_hash)),
                "covenant_authorizing_input": 1
            }]
        });
        let unsigned: RestTransaction = serde_json::from_value(tx_json.clone()).unwrap();
        let token_id =
            tn12_indexer_core::compute_genesis_covenant_id_for_outputs_at_input(&unsigned, 1, &[0])
                .unwrap();
        tx_json["outputs"][0]["covenant_id"] = json!(token_id);
        let start = json!({
            "tokenId": token_id,
            "migrationId": "88".repeat(32),
            "manifestCommitment": "99".repeat(32),
            "holderExtensionCommitment": "44".repeat(32),
            "kcc20TemplateHash": hex::encode(template_hash),
            "reserveCellKas": "50000000",
            "totalSupply": "1000",
            "reserves": [reserve]
        });
        let tx: RestTransaction = serde_json::from_value(tx_json.clone()).unwrap();
        let projected =
            project_snapshot_start_kcc20(&tx, &start, None, template_prefix, template_suffix)
                .unwrap();
        assert_eq!(projected.token_id, hex::decode(&token_id).unwrap());
        assert_eq!(projected.output_states.len(), 1);
        assert_eq!(projected.claim_source, "snapshot-start");

        let mut omitted_binding = tx_json.clone();
        let omitted_output = omitted_binding["outputs"][0].as_object_mut().unwrap();
        omitted_output.remove("covenant_id");
        omitted_output.remove("covenant_authorizing_input");
        omitted_output.remove("covenant");
        let omitted_binding: RestTransaction = serde_json::from_value(omitted_binding).unwrap();
        let projected = project_snapshot_start_kcc20(
            &omitted_binding,
            &start,
            None,
            template_prefix,
            template_suffix,
        )
        .unwrap();
        assert_eq!(projected.token_id, hex::decode(&token_id).unwrap());
        assert_eq!(projected.output_states.len(), 1);

        let mut wrong_covenant_id = tx_json.clone();
        wrong_covenant_id["outputs"][0]["covenant_id"] = json!("00".repeat(32));
        let wrong_covenant_id: RestTransaction = serde_json::from_value(wrong_covenant_id).unwrap();
        assert!(project_snapshot_start_kcc20(
            &wrong_covenant_id,
            &start,
            None,
            template_prefix,
            template_suffix,
        )
        .is_err());

        let mut wrong_authorizing_input = tx_json.clone();
        wrong_authorizing_input["outputs"][0]["covenant_authorizing_input"] = json!(0);
        let wrong_authorizing_input: RestTransaction =
            serde_json::from_value(wrong_authorizing_input).unwrap();
        assert!(project_snapshot_start_kcc20(
            &wrong_authorizing_input,
            &start,
            None,
            template_prefix,
            template_suffix,
        )
        .is_err());

        let mut wrong_script = tx_json.clone();
        wrong_script["outputs"][0]["script_public_key"] =
            json!(format!("aa20{}87", "ab".repeat(32)));
        let wrong_script: RestTransaction = serde_json::from_value(wrong_script).unwrap();
        assert!(project_snapshot_start_kcc20(
            &wrong_script,
            &start,
            None,
            template_prefix,
            template_suffix,
        )
        .is_err());

        let mut extra_family_output = tx_json;
        extra_family_output["outputs"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "index": 1,
                "amount": 1,
                "script_public_key": format!("aa20{}87", "ac".repeat(32)),
                "covenant_id": token_id,
                "covenant_authorizing_input": 1
            }));
        let extra_family_output: RestTransaction =
            serde_json::from_value(extra_family_output).unwrap();
        assert!(project_snapshot_start_kcc20(
            &extra_family_output,
            &start,
            None,
            template_prefix,
            template_suffix,
        )
        .is_err());
    }

    #[test]
    fn snapshot_start_allows_the_controller_to_authorize_its_reserve_and_successor() {
        let controller_id = "11".repeat(32);
        let token_id = "22".repeat(32);
        let transition = json!({
            "action": "start",
            "reserveOutputIndex": "0",
            "controllerOutputIndex": "1",
            "nextState": {
                "controllerCellKas": "50000000",
                "reserveCellKas": "50000000"
            }
        });
        let tx_json = json!({
            "transaction_id": "33".repeat(32),
            "version": 1,
            "inputs": [],
            "outputs": [
                {
                    "index": 0,
                    "amount": 50_000_000,
                    "script_public_key": format!("aa20{}87", "44".repeat(32)),
                    "covenant_authorizing_input": 1,
                    "covenant_id": token_id.clone()
                },
                {
                    "index": 1,
                    "amount": 50_000_000,
                    "script_public_key": format!("aa20{}87", "55".repeat(32)),
                    "covenant_authorizing_input": 1,
                    "covenant_id": controller_id.clone()
                },
                {
                    "index": 2,
                    "amount": 1,
                    "script_public_key": format!("20{}ac", "66".repeat(32))
                }
            ]
        });
        let tx: RestTransaction = serde_json::from_value(tx_json.clone()).unwrap();
        let successor = snapshot_controller_transition_successor(
            &tx,
            1,
            &hex::decode(&controller_id).unwrap(),
            &transition,
        )
        .unwrap()
        .unwrap();
        assert_eq!(successor.0, 1);
        assert_eq!(successor.1, transition["nextState"]);

        let mut omitted_bindings = tx_json.clone();
        for output in omitted_bindings["outputs"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .take(2)
        {
            output
                .as_object_mut()
                .unwrap()
                .remove("covenant_authorizing_input");
            output.as_object_mut().unwrap().remove("covenant_id");
        }
        let omitted_bindings: RestTransaction = serde_json::from_value(omitted_bindings).unwrap();
        assert!(snapshot_controller_transition_successor(
            &omitted_bindings,
            1,
            &hex::decode(&controller_id).unwrap(),
            &transition,
        )
        .unwrap()
        .is_some());

        let mut unexpected_authorization = tx_json;
        unexpected_authorization["outputs"][2]["covenant_authorizing_input"] = json!(1);
        let unexpected_authorization: RestTransaction =
            serde_json::from_value(unexpected_authorization).unwrap();
        assert!(snapshot_controller_transition_successor(
            &unexpected_authorization,
            1,
            &hex::decode(&controller_id).unwrap(),
            &transition,
        )
        .is_err());
    }

    #[test]
    fn snapshot_start_metadata_opening_is_bound_to_the_holder_commitment() {
        let creator = "11".repeat(32);
        let reserve_owner = "22".repeat(32);
        let migration_id = "33".repeat(32);
        let manifest_commitment = "44".repeat(32);
        let reserves = json!([
            {
                "shardIndex": "0",
                "amount": "7175000000000000000",
                "owner": reserve_owner,
                "ownerScheme": 4
            },
            {
                "shardIndex": "1",
                "amount": "7175000000000000000",
                "owner": "23".repeat(32),
                "ownerScheme": 4
            },
            {
                "shardIndex": "2",
                "amount": "7175000000000000000",
                "owner": "24".repeat(32),
                "ownerScheme": 4
            },
            {
                "shardIndex": "3",
                "amount": "7175000000000000000",
                "owner": "25".repeat(32),
                "ownerScheme": 4
            }
        ]);
        let mut claimed = ClaimedDeployment {
            v: 1,
            tmpl: "KCC20".to_string(),
            args: vec![
                ("creator", "byte[32]", json!(creator)),
                (
                    "maxSupply",
                    "u64[2]",
                    json!(["3", "1029883889435672576"]),
                ),
                ("mintLaneCount", "u64", json!("1")),
                (
                    "premintSupply",
                    "u64[2]",
                    json!(["3", "1029883889435672576"]),
                ),
                (
                    "premintRecipient",
                    "byte[32]",
                    json!(reserve_owner.clone()),
                ),
                ("premintOwnerScheme", "u64", json!("4")),
                ("mintPolicy", "u64", json!("0")),
                ("displayScale", "u64", json!("100000000")),
                ("mintPriceSompi", "u64", json!("0")),
                ("treasury", "byte[32]", json!("55".repeat(32))),
                (
                    "protocolFeeRecipient",
                    "byte[32]",
                    json!("66".repeat(32)),
                ),
                ("protocolFeeBps", "u64", json!("0")),
                ("ticker", "string", json!("MIGRA")),
                ("name", "string", json!("MIGRA")),
                ("snapshotReserves", "object", reserves.clone()),
            ]
            .into_iter()
            .map(|(name, arg_type, value)| ClaimedArg {
                name: name.to_string(),
                arg_type: arg_type.to_string(),
                value,
            })
            .collect(),
            meta: None,
        };
        let base_claim = crate::claim::claimed_args_jsonb(&claimed);
        let holder_commitment =
            tn12_indexer_decoder::kcc20_standard::deploy_output_states_from_claimed_args(
                &base_claim,
            )
            .unwrap()[0]
                .state["extensionCommitment"]
                .as_str()
                .unwrap()
                .to_string();
        for (name, value) in [
            ("holderExtensionCommitment", json!(holder_commitment)),
            ("snapshotMigrationId", json!(migration_id)),
            ("snapshotManifestCommitment", json!(manifest_commitment)),
        ] {
            claimed.args.push(ClaimedArg {
                name: name.to_string(),
                arg_type: "value".to_string(),
                value,
            });
        }
        let start = json!({
            "holderExtensionCommitment": holder_commitment,
            "totalSupply": "28700000000000000000",
            "migrationId": migration_id,
            "manifestCommitment": manifest_commitment,
            "reserves": reserves
        });

        assert!(snapshot_start_payload_claim_matches(&start, &claimed));
        let ticker = claimed
            .args
            .iter_mut()
            .find(|arg| arg.name == "ticker")
            .unwrap();
        ticker.value = json!("TWIN");
        assert!(!snapshot_start_payload_claim_matches(&start, &claimed));
    }

    #[test]
    fn merges_persist_stats() {
        let mut total = PersistStats {
            blocks_inserted: 1,
            covenants_inserted: 2,
            utxos_inserted: 3,
            utxos_spent: 4,
            actions_inserted: 5,
        };

        total.merge(PersistStats {
            blocks_inserted: 10,
            covenants_inserted: 20,
            utxos_inserted: 30,
            utxos_spent: 40,
            actions_inserted: 50,
        });

        assert_eq!(total.blocks_inserted, 11);
        assert_eq!(total.covenants_inserted, 22);
        assert_eq!(total.utxos_inserted, 33);
        assert_eq!(total.utxos_spent, 44);
        assert_eq!(total.actions_inserted, 55);
    }

    #[test]
    fn wrapper_claim_verification_matches_canonical_token_id_arg() {
        let canonical = "f6d63104971ad2721641f870ac54dc80ac98ac960db1cf57be7d681973d4f6e3";
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "KCC20Wrapper".to_string(),
            args: vec![ClaimedArg {
                name: "canonicalTokenId".to_string(),
                arg_type: "bytes".to_string(),
                value: json!(canonical),
            }],
            meta: None,
        };

        assert!(claim_matches_decoded_for_template(
            &claimed,
            "KCC20Wrapper",
            &json!({ "canonicalTokenId": canonical })
        ));
        assert!(!claim_matches_decoded_for_template(
            &claimed,
            "KCC20Wrapper",
            &json!({ "canonicalTokenId": "5b0d747910bff259c85d53591d42373da0e0995c297bfdacb9de508a898c6e4e" })
        ));
    }

    #[test]
    fn kcc20_claim_verification_rejects_metadata_substitution() {
        let owner = "11".repeat(32);
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "KCC20".to_string(),
            args: vec![
                ("creator", json!(owner)),
                ("maxSupply", json!("1000")),
                ("premintSupply", json!("0")),
                ("mintPolicy", json!("2")),
                ("displayScale", json!("100")),
                ("mintPriceSompi", json!("0")),
                ("treasury", json!("22".repeat(32))),
                ("protocolFeeRecipient", json!("33".repeat(32))),
                ("protocolFeeBps", json!("200")),
                ("ticker", json!("TEST")),
                ("name", json!("Test Token")),
            ]
            .into_iter()
            .map(|(name, value)| ClaimedArg {
                name: name.to_string(),
                arg_type: "value".to_string(),
                value,
            })
            .collect(),
            meta: None,
        };
        let claimed_json = crate::claim::claimed_args_jsonb(&claimed);
        let outputs = tn12_indexer_decoder::kcc20_standard::deploy_output_states_from_claimed_args(
            &claimed_json,
        )
        .unwrap();
        let mut decoded = outputs[0].state.clone();
        decoded["standard"] = json!("KCC20");

        assert!(claim_matches_decoded_for_template(
            &claimed, "KCC20", &decoded
        ));

        decoded["extension"]["ticker"] = json!("FAKE");
        assert!(!claim_matches_decoded_for_template(
            &claimed, "KCC20", &decoded
        ));
    }

    #[test]
    fn fixed_kcc20_claim_verification_matches_real_constructor_shape() {
        let owner = "11".repeat(32);
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "KCC20".to_string(),
            args: vec![
                ("creator", json!(owner.clone())),
                ("maxSupply", json!("1000")),
                ("premintSupply", json!("1000")),
                ("premintRecipient", json!(owner)),
                ("premintOwnerScheme", json!("0")),
                ("mintPolicy", json!("0")),
                ("displayScale", json!("100")),
                ("mintPriceSompi", json!("0")),
                ("treasury", json!("22".repeat(32))),
                ("protocolFeeRecipient", json!("33".repeat(32))),
                ("protocolFeeBps", json!("200")),
                ("ticker", json!("FIXED")),
                ("name", json!("Fixed Token")),
            ]
            .into_iter()
            .map(|(name, value)| ClaimedArg {
                name: name.to_string(),
                arg_type: "value".to_string(),
                value,
            })
            .collect(),
            meta: None,
        };
        let claimed_json = crate::claim::claimed_args_jsonb(&claimed);
        let output = tn12_indexer_decoder::kcc20_standard::deploy_output_states_from_claimed_args(
            &claimed_json,
        )
        .unwrap()
        .remove(0);
        let reveal =
            tn12_indexer_decoder::kcc20_standard::script_for_state_value(&output.state).unwrap();
        let decoded = classify_reveal(&tn12_indexer_decoder::default_registry(), &[], &reveal)
            .unwrap()
            .args;

        assert!(claim_matches_decoded_for_template(
            &claimed, "KCC20", &decoded
        ));
    }

    #[test]
    fn mintable_claim_verification_ignores_mutable_extension_fields() {
        let owner = "11".repeat(32);
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "KCC20".to_string(),
            args: vec![
                ("creator", json!(owner)),
                ("maxSupply", json!("1000")),
                ("premintSupply", json!("0")),
                ("mintPolicy", json!("2")),
                ("displayScale", json!("100")),
                ("mintPriceSompi", json!("0")),
                ("treasury", json!("22".repeat(32))),
                ("protocolFeeRecipient", json!("33".repeat(32))),
                ("protocolFeeBps", json!("200")),
                ("ticker", json!("TEST")),
                ("name", json!("Test Token")),
            ]
            .into_iter()
            .map(|(name, value)| ClaimedArg {
                name: name.to_string(),
                arg_type: "value".to_string(),
                value,
            })
            .collect(),
            meta: None,
        };
        let claimed_json = crate::claim::claimed_args_jsonb(&claimed);
        let outputs = tn12_indexer_decoder::kcc20_standard::deploy_output_states_from_claimed_args(
            &claimed_json,
        )
        .unwrap();
        let mut decoded = json!({
            "standard": "KCC20",
            "extension": outputs[0].state["extension"].clone(),
        });
        decoded["extension"]["remainingSupply"] = json!("700");
        decoded["extension"]["publicMintActive"] = json!(true);

        assert!(claim_matches_decoded_for_template(
            &claimed, "KCC20", &decoded
        ));
        decoded["extension"]["ticker"] = json!("FAKE");
        assert!(!claim_matches_decoded_for_template(
            &claimed, "KCC20", &decoded
        ));
    }

    #[test]
    fn transient_persist_error_is_detected_through_context() {
        let err = anyhow::Error::new(TransientPersistError::writer_lock_busy("test operation"))
            .context("outer scanner context");

        assert!(is_transient_persist_error(&err));
    }

    #[test]
    fn transient_persist_detector_matches_postgres_pressure_messages() {
        for message in [
            "canceling statement due to lock timeout",
            "canceling statement due to statement timeout",
            "deadlock detected",
            "could not serialize access due to concurrent update",
            "pool timed out while waiting for an open connection",
        ] {
            let err = anyhow::anyhow!(message).context("outer scanner context");
            assert!(
                is_transient_persist_error(&err),
                "expected transient persist pressure for {message}"
            );
        }
    }
}
