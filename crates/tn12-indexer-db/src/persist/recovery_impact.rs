//! Bounded removal footprints. Discovery grants no write authority: the whole
//! footprint is checked again under the writer lock, in the removal transaction.
use super::{PgPersister, RevertStats};
use anyhow::{ensure, Result};
use sqlx::{PgConnection, Postgres, Transaction};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBlockImpact {
    pub block_hash: String,
    pub transaction_ids: Vec<String>,
    pub descendants: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("recovery footprint exceeds bounded impact limit")]
pub struct RecoveryImpactLimit;

#[derive(Debug, thiserror::Error)]
#[error("canonical recovery must replan: {0}")]
pub struct RecoveryReplanRequired(pub &'static str);

pub(super) async fn load(conn: &mut PgConnection, hash: &str) -> Result<RecoveryBlockImpact> {
    let bytes = hex::decode(hash)?;
    ensure!(bytes.len() == 32, "invalid recovery block hash");
    let ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT txid FROM (SELECT txid FROM covenant_actions WHERE block_hash=$1 \
         UNION SELECT txid FROM covenant_utxos WHERE created_block=$1 \
         UNION SELECT spent_by_txid FROM covenant_utxos WHERE spent_block=$1 AND spent_by_txid IS NOT NULL \
         UNION SELECT genesis_txid FROM covenants WHERE genesis_block=$1) affected LIMIT 257"
    ).bind(&bytes).fetch_all(&mut *conn).await?;
    // A genesis removal cascades through its covenant FK as well as spend
    // edges. Include those blocks too or a rollback can silently erase siblings.
    // Select the genesis footprint once. Repeating the covenants join lets the
    // action branch choose a whole-table parallel scan even for an absent root.
    let descendants: Vec<Vec<u8>> = sqlx::query_scalar(
        "WITH roots AS MATERIALIZED (SELECT covenant_id FROM covenants WHERE genesis_block=$1) \
         SELECT hash FROM (SELECT spent_block AS hash FROM covenant_utxos \
         WHERE created_block=$1 AND spent_block IS NOT NULL AND spent_block<>$1 \
         UNION SELECT u.created_block FROM roots c JOIN covenant_utxos u USING(covenant_id) \
         WHERE u.created_block<>$1 \
         UNION SELECT u.spent_block FROM roots c JOIN covenant_utxos u USING(covenant_id) \
         WHERE u.spent_block IS NOT NULL AND u.spent_block<>$1 \
         UNION SELECT a.block_hash FROM roots c JOIN covenant_actions a USING(covenant_id) \
         WHERE a.block_hash<>$1) affected LIMIT 257",
    )
    .bind(&bytes)
    .fetch_all(&mut *conn)
    .await?;
    ensure!(
        ids.len() <= 256 && descendants.len() <= 256,
        RecoveryImpactLimit
    );
    ensure!(
        ids.iter().chain(&descendants).all(|id| id.len() == 32),
        "invalid indexed recovery identity"
    );
    Ok(RecoveryBlockImpact {
        block_hash: hash.to_owned(),
        transaction_ids: ids.into_iter().map(hex::encode).collect(),
        descendants: descendants.into_iter().map(hex::encode).collect(),
    })
}

pub(super) async fn validate_locked(
    tx: &mut Transaction<'_, Postgres>,
    impacts: &[RecoveryBlockImpact],
) -> Result<()> {
    ensure!(impacts.len() <= 256, RecoveryImpactLimit);
    let blocks: BTreeSet<_> = impacts.iter().map(|i| i.block_hash.as_str()).collect();
    ensure!(
        blocks.len() == impacts.len(),
        "duplicate recovery removal block"
    );
    let mut all_ids = BTreeSet::new();
    let mut removed = BTreeSet::new();
    for planned in impacts {
        // The caller provides descendants before parents, including shared
        // descendants exactly once. Never trust ordering by blue score alone.
        ensure!(
            planned
                .descendants
                .iter()
                .all(|h| removed.contains(h.as_str())),
            RecoveryReplanRequired("removal order does not cover every descendant")
        );
        let expected: BTreeSet<_> = planned.transaction_ids.iter().collect();
        all_ids.extend(expected.iter().copied());
        ensure!(all_ids.len() <= 256, RecoveryImpactLimit);
        let actual = load(&mut *tx, &planned.block_hash).await?;
        ensure!(
            actual
                .transaction_ids
                .iter()
                .all(|id| expected.contains(id)),
            RecoveryReplanRequired("new indexed transaction appeared after discovery")
        );
        // Even a new edge inside the closure requires a new plan if the child
        // would be removed after its parent.
        ensure!(
            actual
                .descendants
                .iter()
                .all(|h| removed.contains(h.as_str())),
            RecoveryReplanRequired("indexed descendant changed after discovery")
        );
        removed.insert(planned.block_hash.as_str());
    }
    Ok(())
}

impl PgPersister {
    pub(super) async fn load_recovery_impact(&self, hash: &str) -> Result<RecoveryBlockImpact> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL jit=off").execute(&mut *tx).await?;
        let result = load(&mut tx, hash).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub(super) async fn remove_recovery_impact(
        &self,
        impacts: &[RecoveryBlockImpact],
    ) -> Result<Vec<RevertStats>> {
        let hashes = impacts
            .iter()
            .map(|i| hex::decode(&i.block_hash))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // The removal transaction is atomic. Canceling it at a fixed wall-clock
        // deadline can roll back the same valid footprint on every retry.
        // Wait for its outcome before yielding; the retained journal still
        // resolves an interrupted or uncertain commit on the next attempt.
        let result = self.revert_blocks_locked_checked(&hashes, Some(impacts)).await;
        tokio::task::yield_now().await;
        result
    }
}

#[cfg(test)]
#[path = "recovery_impact_tests.rs"]
mod tests;
