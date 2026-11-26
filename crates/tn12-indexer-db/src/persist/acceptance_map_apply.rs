//! Transactional transition for historical acceptance maps.
//! Preview exercises the actual writes and triggers, then always rolls back.
use super::acceptance_cohort::verify_cohort;
use super::{AcceptanceReconciliationStats, HistoricalAcceptanceMapProof, PgPersister};
use anyhow::{ensure, Context, Result};
use sqlx::{Postgres, Transaction};
use std::future::Future;
use tokio::time::{Duration, Instant};
#[path = "acceptance_transition_batch.rs"]
mod batch;
#[cfg(test)]
#[path = "acceptance_transition_reference.rs"]
pub(super) mod reference;

// Bound each sort/hash node and prevent parallel workers multiplying its memory.
// These short transactions cannot amortize JIT compilation of the cohort guard.
// PostgreSQL spills larger bounded cohorts to temporary files. Callers may
// opt into a deadline when they share a writer with latency-sensitive work.
pub(super) async fn set_comparison_work_limits(conn: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("SELECT set_config('work_mem','4MB',true),set_config('hash_mem_multiplier','1',true),set_config('max_parallel_workers_per_gather','0',true),set_config('jit','off',true)")
        .execute(&mut **conn).await?;
    Ok(())
}

pub(super) async fn remaining_budget(
    conn: &mut Transaction<'_, Postgres>,
    deadline: impl Into<Option<Instant>>,
) -> Result<()> {
    let Some(deadline) = deadline.into() else {
        sqlx::query("SELECT set_config('statement_timeout','0',true)")
            .execute(&mut **conn)
            .await?;
        return Ok(());
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("historical acceptance writer deadline exceeded"))?;
    ensure!(
        remaining.as_millis() > 1,
        "historical acceptance writer deadline exhausted"
    );
    sqlx::query("SELECT set_config('statement_timeout',$1,true)")
        .bind(format!("{}ms", remaining.as_millis().min(5_000)))
        .execute(&mut **conn)
        .await?;
    Ok(())
}

async fn with_optional_deadline<F: Future>(
    deadline: Option<Instant>,
    future: F,
) -> std::result::Result<F::Output, tokio::time::error::Elapsed> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future).await,
        None => Ok(future.await),
    }
}

// Build immutable proof-derived inputs before taking the shared writer lock.
// Database state is still re-read and checked under that lock before any write.
pub(super) struct PreparedTransition {
    ids: Vec<Vec<u8>>,
    target_hashes: Vec<Vec<u8>>,
    mapping: serde_json::Value,
    block_evidence: serde_json::Value,
    inputs: serde_json::Value,
    acceptance_blocks: Vec<Vec<u8>>,
    audit: serde_json::Value,
}

impl PreparedTransition {
    pub(super) fn new(proof: &HistoricalAcceptanceMapProof) -> Self {
        let targets = proof.source.targets();
        let ids: Vec<_> = targets.iter().map(|t| t.transaction_id.clone()).collect();
        let target_hashes: Vec<_> = targets.iter().map(|t| t.target_hash.clone()).collect();
        let id_set: std::collections::HashSet<&[u8]> = ids.iter().map(Vec::as_slice).collect();
        let mapping=serde_json::Value::Array(targets.iter().map(|t|serde_json::json!({
        "old":hex::encode(&t.old_hash),"txid":hex::encode(&t.transaction_id),
        "target":hex::encode(&t.target_hash),"score":t.target_score,"time":t.target_time_ms,
    })).collect());
        let block_evidence=serde_json::Value::Array(proof.source.window().removed.iter()
        .chain(proof.source.window().canonical.iter().map(|b|&b.block))
        .map(|b|serde_json::json!({"hash":hex::encode(&b.hash),"score":b.blue_score,"time":b.timestamp,"canonical":b.is_chain_block})).collect());
        let inputs=serde_json::Value::Array(proof.source.window().canonical.iter().flat_map(|b|b.inputs.iter())
        .filter(|i|id_set.contains(i.transaction_id.as_slice())).map(|i|serde_json::json!({"txid":hex::encode(&i.transaction_id),"prev":hex::encode(&i.previous_txid),"vout":i.previous_vout,"amount":i.previous_amount,"script":i.previous_script.as_ref().map(hex::encode)})).collect());
        let mut acceptance_blocks = proof.cohort.old_hashes().to_vec();
        acceptance_blocks.extend(target_hashes.iter().cloned());
        acceptance_blocks.sort();
        acceptance_blocks.dedup();
        let window = proof.source.window();
        let audit = serde_json::json!({"version":1,"removed":window.removed,"canonical_blocks":window.canonical.iter().map(|b|&b.block).collect::<Vec<_>>(),"references":proof.cohort.reference_count(),"transactions":ids.len()});
        Self {
            ids,
            target_hashes,
            mapping,
            block_evidence,
            inputs,
            acceptance_blocks,
            audit,
        }
    }
}

impl PgPersister {
    /// Executes the complete tentative transition under the shared writer lock,
    /// then rolls it back. This is not a repair or a source-freshness check.
    pub async fn preview_historical_acceptance_map(
        &self,
        proof: &HistoricalAcceptanceMapProof,
    ) -> Result<AcceptanceReconciliationStats> {
        let transition_data = PreparedTransition::new(proof);
        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        set_comparison_work_limits(&mut conn).await?;
        stage_transition(&mut conn, proof, &transition_data).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        let started = Instant::now();
        let deadline = started + Duration::from_millis(350);
        let result = tokio::time::timeout_at(deadline, async {
            if let Some(stats) =
                super::acceptance_map_state::classify_applied(&mut conn, proof, deadline).await?
            {
                Ok(stats)
            } else {
                transition(&mut conn, proof, &transition_data, deadline).await
            }
        })
        .await;
        conn.rollback()
            .await
            .context("roll back historical acceptance preview")?;
        let hold = started.elapsed();
        ensure!(
            hold <= Duration::from_millis(400),
            "historical acceptance preview exceeded writer hold budget: {}us",
            hold.as_micros()
        );
        result.context("historical acceptance preview exceeded application deadline")?
    }
}

pub(super) async fn stage_transition(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
    prepared: &PreparedTransition,
) -> Result<()> {
    batch::stage(conn, proof, prepared).await
}

pub(super) async fn transition(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
    _prepared: &PreparedTransition,
    deadline: impl Into<Option<Instant>>,
) -> Result<AcceptanceReconciliationStats> {
    remaining_budget(conn, deadline).await?;
    batch::execute(conn, proof).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalAcceptanceOutcome {
    Applied,
    NotApplied,
}

#[derive(Debug, thiserror::Error)]
#[error("historical acceptance commit outcome is unknown for proof {proof_hash}: {detail}; classify under the writer lock before retrying")]
pub struct HistoricalAcceptanceOutcomeUnknown {
    pub proof_hash: String,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
#[error("historical acceptance commit was not applied; the original cohort was verified under the writer lock")]
pub struct HistoricalAcceptanceCommitNotApplied;

impl PgPersister {
    /// Reclassifies an uncertain commit on a fresh connection while holding the
    /// same lock as every writer. A missing ledger alone never proves rollback.
    pub async fn classify_historical_acceptance_outcome(
        &self,
        proof: &HistoricalAcceptanceMapProof,
    ) -> Result<HistoricalAcceptanceOutcome> {
        // Classification resolves a prior commit; source renewal is irrelevant.
        let mut inspector = self.clone();
        inspector.rest_removal_guard = None;
        let budget = self.historical_acceptance_hold_budget;
        let outer_deadline = (!budget.is_zero())
            .then(|| Instant::now() + budget + Duration::from_secs(3));
        let inspected=with_optional_deadline(outer_deadline,async {
            let mut conn=self.pool.begin().await?;
            Self::set_persist_query_limits(&mut conn).await?;
            set_comparison_work_limits(&mut conn).await?;
            inspector.acquire_persist_writer_lock(&mut conn).await?;
            let started=Instant::now();
            let deadline=(!budget.is_zero()).then(|| started+budget);
            let state=with_optional_deadline(deadline,async {
                if super::acceptance_map_state::classify_applied(&mut conn,proof,deadline).await?.is_some() {
                    return Ok(HistoricalAcceptanceOutcome::Applied);
                }
                remaining_budget(&mut conn,deadline).await?;
                let other:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM historical_acceptance_map_sources WHERE old_hash=ANY($1::bytea[]))")
                    .bind(proof.cohort.old_hashes()).fetch_one(&mut *conn).await?;
                ensure!(!other,"historical acceptance source has another recorded proof");
                verify_cohort(&mut conn,&proof.cohort,deadline).await
                    .context("uncertain historical acceptance cohort no longer matches original state")?;
                Ok::<_,anyhow::Error>(HistoricalAcceptanceOutcome::NotApplied)
            }).await;
            conn.rollback().await?;
            if !budget.is_zero() {
                ensure!(started.elapsed()<=budget+Duration::from_millis(50),"historical acceptance classification exceeded writer hold budget");
            }
            state.context("historical acceptance classification deadline")?
        }).await;
        match inspected {
            Ok(Ok(state)) => Ok(state),
            other => Err(HistoricalAcceptanceOutcomeUnknown {
                proof_hash: hex::encode(proof.proof_hash()),
                detail: match other {
                    Ok(Err(error)) => format!("{error:#}"),
                    Err(error) => error.to_string(),
                    _ => unreachable!(),
                },
            }
            .into()),
        }
    }

    pub(super) async fn recover_historical_acceptance_commit(
        &self,
        proof: &HistoricalAcceptanceMapProof,
        mut stats: AcceptanceReconciliationStats,
    ) -> Result<AcceptanceReconciliationStats> {
        match self.classify_historical_acceptance_outcome(proof).await? {
            HistoricalAcceptanceOutcome::Applied => {
                stats.already_reconciled = true;
                Ok(stats)
            }
            HistoricalAcceptanceOutcome::NotApplied => {
                Err(HistoricalAcceptanceCommitNotApplied.into())
            }
        }
    }

    pub async fn reconcile_historical_acceptance_map(
        &self,
        proof: &HistoricalAcceptanceMapProof,
    ) -> Result<AcceptanceReconciliationStats> {
        self.require_rest_guard_hashes(proof.source().targets().iter().map(|target|target.target_hash.as_slice()))?;
        let transition_data = PreparedTransition::new(proof);
        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        set_comparison_work_limits(&mut conn).await?;
        stage_transition(&mut conn, proof, &transition_data).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        let started = Instant::now();
        let budget = self.historical_acceptance_hold_budget;
        let deadline = (!budget.is_zero()).then(|| started + budget);
        let prepared = with_optional_deadline(deadline, async {
            if let Some(stats) =
                super::acceptance_map_state::classify_applied(&mut conn, proof, deadline).await?
            {
                return Ok((stats, false));
            }
            let stats = transition(&mut conn, proof, &transition_data, deadline).await?;
            remaining_budget(&mut conn, deadline).await?;
            Ok::<_, anyhow::Error>((stats, true))
        })
        .await;
        let (stats, changed) = match prepared {
            Ok(Ok(prepared)) => prepared,
            failure => {
                conn.rollback()
                    .await
                    .context("rollback uncommitted historical acceptance map")?;
                if !budget.is_zero() {
                    ensure!(
                        started.elapsed() <= budget + Duration::from_millis(50),
                        "historical acceptance rollback exceeded writer hold budget"
                    );
                }
                return match failure {
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(error).context("historical acceptance transition deadline"),
                    _ => unreachable!(),
                };
            }
        };
        if !changed {
            conn.rollback().await?;
            if !budget.is_zero() {
                ensure!(
                    started.elapsed() <= budget + Duration::from_millis(50),
                    "historical acceptance idempotence exceeded writer hold budget"
                );
            }
            return Ok(stats);
        }
        // Once COMMIT is sent, loss of acknowledgement is not a rollback.
        // Consume this connection and inspect from a fresh locked transaction.
        let commit = with_optional_deadline(deadline, conn.commit()).await;
        match commit {
            Ok(Ok(())) => {
                let held = started.elapsed();
                tracing::info!(proof_hash=%hex::encode(proof.proof_hash()),writer_lock_held_us=held.as_micros() as u64,created_outputs=stats.created_outputs,spent_inputs=stats.spent_inputs,actions=stats.actions,"historical acceptance map committed");
                if !budget.is_zero() {
                    ensure!(
                        held <= budget + Duration::from_millis(50),
                        "historical acceptance map committed, but observed writer hold exceeded its budget"
                    );
                }
                Ok(stats)
            }
            uncertain => {
                let detail = match uncertain {
                    Ok(Err(error)) => error.to_string(),
                    Err(error) => error.to_string(),
                    _ => unreachable!(),
                };
                tracing::warn!(proof_hash=%hex::encode(proof.proof_hash()),error=%detail,"historical acceptance commit acknowledgement failed; classifying outcome");
                self.recover_historical_acceptance_commit(proof, stats)
                    .await
            }
        }
    }
}

#[cfg(test)]
#[path = "acceptance_transition_tests.rs"]
mod batch_tests;
