//! Exact persisted-row snapshots for historical acceptance repair.
use super::PgPersister;
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

const MAX_REFERENCES: usize = 8192;
const MAX_COHORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPARISON_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct HistoricalAcceptanceReference {
    pub kind: String,
    pub old_hash: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub row: Value,
}

/// Constructed exclusively from a complete bounded database read, never from
/// caller-supplied transaction IDs. Full rows bind descendant/decoded state too.
#[derive(Debug, Clone)]
pub struct HistoricalAcceptanceCohort {
    pub(super) old_hashes: Vec<Vec<u8>>,
    pub(super) references: Vec<HistoricalAcceptanceReference>,
    pub(super) digest: [u8; 32],
    pub(super) normalized_rows: Vec<u8>,
    // Private, bounded PostgreSQL row text. Never part of the normalized proof.
    pub(super) comparison_rows: Option<String>,
}
impl HistoricalAcceptanceCohort {
    pub fn normalized_rows(&self) -> &[u8] {
        &self.normalized_rows
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
    pub fn old_hashes(&self) -> &[Vec<u8>] {
        &self.old_hashes
    }
    pub fn transactions(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.references
            .iter()
            .map(|r| (r.old_hash.clone(), r.transaction_id.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

impl PgPersister {
    pub async fn historical_acceptance_cohort(
        &self,
        old_hashes: &[Vec<u8>],
    ) -> Result<HistoricalAcceptanceCohort> {
        let mut conn = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        Self::set_persist_query_limits(&mut conn).await?;
        let cohort = read_cohort(&mut conn, old_hashes, false, None).await?;
        conn.rollback().await?;
        Ok(cohort)
    }
}

pub(super) async fn read_cohort(
    conn: &mut Transaction<'_, Postgres>,
    old_hashes: &[Vec<u8>],
    lock: bool,
    deadline: Option<tokio::time::Instant>,
) -> Result<HistoricalAcceptanceCohort> {
    ensure!(
        !old_hashes.is_empty()
            && old_hashes.len() <= MAX_REFERENCES
            && old_hashes.iter().all(|h| h.len() == 32),
        "invalid old acceptance block set"
    );
    let mut old_hashes = old_hashes.to_vec();
    old_hashes.sort();
    old_hashes.dedup();
    let mut references = Vec::new();
    let mut total_bytes = 0usize;
    let mut raw_bytes = 0usize;
    let mut comparison_rows = Vec::new();
    // Identifiers come only from this static list. Each read rejects truncation
    // and suppresses oversized payload transfer; the combined cohort is bounded.
    for (kind, table, block, txid, order) in [
        (
            "created",
            "covenant_utxos",
            "created_block",
            "txid",
            "txid,vout",
        ),
        (
            "spent",
            "covenant_utxos",
            "spent_block",
            "spent_by_txid",
            "txid,vout",
        ),
        ("action", "covenant_actions", "block_hash", "txid", "id"),
        (
            "genesis",
            "covenants",
            "genesis_block",
            "genesis_txid",
            "covenant_id",
        ),
    ] {
        let locking = if lock { " FOR UPDATE" } else { "" };
        let sql=format!("WITH selected AS MATERIALIZED (SELECT * FROM {table} WHERE {block}=ANY($1::bytea[]) ORDER BY {order} LIMIT 8193{locking}), payload AS MATERIALIZED (SELECT {block} AS old_hash,{txid} AS txid,to_jsonb(s) AS data FROM selected s), bounds AS (SELECT COALESCE(sum(octet_length(data::text)),0) AS bytes FROM payload) SELECT old_hash,txid,CASE WHEN bounds.bytes <= 16777216 THEN data::text ELSE NULL END FROM payload CROSS JOIN bounds");
        if let Some(deadline) = deadline {
            super::acceptance_map_apply::remaining_budget(conn, deadline).await?;
        }
        let rows: Vec<(Vec<u8>, Option<Vec<u8>>, Option<String>)> =
            sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(&old_hashes)
                .fetch_all(&mut **conn)
                .await
                .context("capture historical acceptance cohort")?;
        ensure!(
            references.len() + rows.len() <= MAX_REFERENCES,
            "historical acceptance cohort exceeds reference bound"
        );
        for (old_hash, transaction_id, row) in rows {
            let transaction_id = transaction_id.filter(|id| id.len() == 32).ok_or_else(|| {
                anyhow::anyhow!("historical acceptance reference has no valid transaction ID")
            })?;
            let row = row.ok_or_else(|| {
                anyhow::anyhow!("historical acceptance cohort exceeds byte bound")
            })?;
            raw_bytes = raw_bytes
                .checked_add(row.len())
                .context("historical comparison byte overflow")?;
            ensure!(
                raw_bytes <= MAX_COHORT_BYTES,
                "historical comparison exceeds raw byte bound"
            );
            let value: Value =
                serde_json::from_str(&row).context("decode historical cohort row")?;
            comparison_rows.push(serde_json::json!({"kind":kind,"data":row}));
            let reference = HistoricalAcceptanceReference {
                kind: kind.into(),
                old_hash,
                transaction_id,
                row: value,
            };
            total_bytes = total_bytes
                .checked_add(serde_json::to_vec(&reference)?.len())
                .ok_or_else(|| anyhow::anyhow!("historical acceptance cohort byte overflow"))?;
            ensure!(
                total_bytes <= MAX_COHORT_BYTES,
                "historical acceptance cohort exceeds byte bound"
            );
            references.push(reference);
        }
    }
    ensure!(
        !references.is_empty()
            && old_hashes
                .iter()
                .all(|h| references.iter().any(|r| &r.old_hash == h)),
        "historical acceptance source has no stored references"
    );
    references.sort_by_cached_key(|r| serde_json::to_vec(r).expect("serializable cohort row"));
    let normalized_rows = serde_json::to_vec(&(&old_hashes, &references))?;
    ensure!(
        normalized_rows.len() <= MAX_COHORT_BYTES,
        "historical acceptance cohort exceeds normalized byte bound"
    );
    let digest = tn12_indexer_core::blake2b_256(&normalized_rows);
    let comparison_rows = serde_json::to_string(&comparison_rows)?;
    ensure!(
        comparison_rows.len() <= MAX_COMPARISON_BYTES,
        "historical comparison exceeds encoded byte bound"
    );
    Ok(HistoricalAcceptanceCohort {
        old_hashes,
        references,
        digest,
        normalized_rows,
        comparison_rows: Some(comparison_rows),
    })
}

/// Revalidate all captured rows while the caller holds the shared writer lock.
pub(super) async fn verify_cohort(
    conn: &mut Transaction<'_, Postgres>,
    expected: &HistoricalAcceptanceCohort,
    deadline: impl Into<Option<tokio::time::Instant>>,
) -> Result<()> {
    let payload = expected
        .comparison_rows
        .as_ref()
        .context("historical cohort lacks exact comparison rows")?;
    ensure!(
        !expected.references.is_empty()
            && expected.references.len() <= MAX_REFERENCES
            && payload.len() <= MAX_COMPARISON_BYTES,
        "historical comparison exceeds bounds"
    );
    super::acceptance_map_apply::remaining_budget(conn, deadline).await?;
    let matches: bool = sqlx::query_scalar(concat!(
        "WITH expected_input AS (SELECT $1::bytea[] old_hashes,$2::jsonb comparison),",
        include_str!("acceptance_cohort_guard.sql")
    ))
    .bind(expected.old_hashes())
    .bind(payload)
    .fetch_one(&mut **conn)
    .await?;
    ensure!(
        matches,
        "historical acceptance cohort changed after proof capture"
    );
    Ok(())
}

#[cfg(test)]
#[path = "acceptance_cohort_tests.rs"]
mod exact_tests;
