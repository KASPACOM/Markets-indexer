//! Large individual block footprints. Canonical writes are fenced while the
//! bounded pages are discovered, reverted, replayed, and finally verified.
use super::paged_recovery::{decode_hash, lock_intent_and_owner};
use super::{PagedRecoveryOwner, PgPersister, RecoveryReplanRequired, RevertStats};
use anyhow::{ensure, Result};
use sqlx::{PgConnection, Postgres, Transaction};

const IDS: &str = "SELECT txid AS item FROM covenant_actions WHERE block_hash=$1 \
 UNION SELECT txid FROM covenant_utxos WHERE created_block=$1 \
 UNION SELECT spent_by_txid FROM covenant_utxos WHERE spent_block=$1 AND spent_by_txid IS NOT NULL \
 UNION SELECT genesis_txid FROM covenants WHERE genesis_block=$1";
const CHILDREN: &str = "WITH roots AS MATERIALIZED (SELECT covenant_id FROM covenants WHERE genesis_block=$1) \
 SELECT spent_block AS item FROM covenant_utxos WHERE created_block=$1 AND spent_block IS NOT NULL AND spent_block<>$1 \
 UNION SELECT u.created_block FROM roots c JOIN covenant_utxos u USING(covenant_id) WHERE u.created_block<>$1 \
 UNION SELECT u.spent_block FROM roots c JOIN covenant_utxos u USING(covenant_id) WHERE u.spent_block IS NOT NULL AND u.spent_block<>$1 \
 UNION SELECT a.block_hash FROM roots c JOIN covenant_actions a USING(covenant_id) WHERE a.block_hash<>$1";

async fn missing_items(
    conn: &mut PgConnection,
    owner: &PagedRecoveryOwner,
    hash: &[u8],
    kind: &str,
) -> Result<Vec<Vec<u8>>> {
    let sql = if kind == "transaction" { IDS } else { CHILDREN };
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT item FROM ({sql}) actual WHERE NOT EXISTS(SELECT 1 FROM tn10_live_recovery_block_items s WHERE s.intent_key=$2 AND s.block_hash=$1 AND s.kind=$3 AND s.item=actual.item) ORDER BY item LIMIT 32"
    ))).bind(hash).bind(&owner.intent_key).bind(kind).fetch_all(conn).await?)
}

impl PagedRecoveryOwner {
    pub async fn stage_chunked_block(
        &self,
        writer: &PgPersister,
        hash: &str,
        score: i64,
        canonical: bool,
    ) -> Result<()> {
        let hash = decode_hash(hash)?;
        let pool = writer.paged_recovery_pool();
        let mut tx = pool.begin().await?;
        PgPersister::set_persist_query_limits(&mut tx).await?;
        writer
            .acquire_recovery_writer_lock(&mut tx, Some(self))
            .await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_plans p JOIN tn10_live_recovery_frontier f USING(intent_key) WHERE p.intent_key=$1 AND p.phase='discover' AND f.block_hash=$2)")
            .bind(&self.intent_key).bind(&hash).fetch_one(&mut *tx).await?;
        ensure!(valid, "chunked block is outside discovery frontier");
        sqlx::query(
            "UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE WHERE intent_key=$1",
        )
        .bind(&self.intent_key)
        .execute(&mut *tx)
        .await?;
        let inserted = sqlx::query("INSERT INTO tn10_live_recovery_blocks(intent_key,block_hash,blue_score,transaction_ids,descendants,source_is_chain_block,chunked) VALUES($1,$2,$3,'[]','[]',$4,TRUE) ON CONFLICT DO NOTHING")
            .bind(&self.intent_key).bind(&hash).bind(score).bind(canonical).execute(&mut *tx).await?.rows_affected();
        let same: bool = sqlx::query_scalar("SELECT chunked AND blue_score=$3 AND source_is_chain_block=$4 FROM tn10_live_recovery_blocks WHERE intent_key=$1 AND block_hash=$2")
            .bind(&self.intent_key).bind(&hash).bind(score).bind(canonical).fetch_one(&mut *tx).await?;
        ensure!(same, "chunked block source evidence changed");
        sqlx::query("UPDATE tn10_live_recovery_plans SET discovered_blocks=discovered_blocks+$2 WHERE intent_key=$1")
            .bind(&self.intent_key).bind(inserted as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        loop {
            self.heartbeat(pool).await?;
            // The exclusive plan prevents canonical mutations between read
            // pages. SQL result size, memory, and checkpoint writes are bounded.
            let mut read = pool.begin().await?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *read)
                .await?;
            sqlx::query("SET LOCAL statement_timeout='2s'")
                .execute(&mut *read)
                .await?;
            let ids = missing_items(&mut read, self, &hash, "transaction").await?;
            let children = missing_items(&mut read, self, &hash, "descendant").await?;
            read.commit().await?;
            let mut tx = pool.begin().await?;
            lock_intent_and_owner(&mut tx, self).await?;
            let discovering: bool = sqlx::query_scalar(
                "SELECT phase='discover' FROM tn10_live_recovery_plans WHERE intent_key=$1",
            )
            .bind(&self.intent_key)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(discovering, "chunked discovery phase changed");
            for (kind, items) in [("transaction", &ids), ("descendant", &children)] {
                sqlx::query("INSERT INTO tn10_live_recovery_block_items(intent_key,block_hash,kind,item) SELECT $1,$2,$3,unnest($4::bytea[]) ON CONFLICT DO NOTHING")
                    .bind(&self.intent_key).bind(&hash).bind(kind).bind(items).execute(&mut *tx).await?;
            }
            sqlx::query("INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) SELECT $1,unnest($2::bytea[]) ON CONFLICT DO NOTHING")
                .bind(&self.intent_key).bind(&ids).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) SELECT $1,unnest($2::bytea[]) ON CONFLICT DO NOTHING")
                .bind(&self.intent_key).bind(&children).execute(&mut *tx).await?;
            if ids.is_empty() && children.is_empty() {
                sqlx::query("UPDATE tn10_live_recovery_frontier SET processed=TRUE WHERE intent_key=$1 AND block_hash=$2")
                    .bind(&self.intent_key).bind(&hash).execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok(());
            }
            tx.commit().await?;
        }
    }

    /// Select a whole transaction whose created effects no longer have a live
    /// spender and whose genesis families have no sibling effects to cascade.
    pub(super) async fn chunked_next_tx(
        &self,
        conn: &mut PgConnection,
        hash: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar("SELECT s.item FROM tn10_live_recovery_block_items s WHERE s.intent_key=$2 AND s.block_hash=$1 AND s.kind='transaction' AND NOT s.removed \
          AND NOT EXISTS(SELECT 1 FROM covenant_utxos u WHERE u.created_block=$1 AND u.txid=s.item AND u.spent_by_txid IS NOT NULL AND u.spent_by_txid<>s.item) \
          AND NOT EXISTS(SELECT 1 FROM covenants c JOIN covenant_utxos u USING(covenant_id) WHERE c.genesis_block=$1 AND c.genesis_txid=s.item AND u.txid<>s.item) \
          AND NOT EXISTS(SELECT 1 FROM covenants c JOIN covenant_actions a USING(covenant_id) WHERE c.genesis_block=$1 AND c.genesis_txid=s.item AND a.txid<>s.item) \
          ORDER BY s.item LIMIT 1")
            .bind(hash).bind(&self.intent_key).fetch_optional(conn).await?)
    }

    pub(super) async fn revert_chunked_locked(
        &self,
        writer: &PgPersister,
        tx: &mut Transaction<'_, Postgres>,
        hash: &[u8],
        requested: &[String],
    ) -> Result<(RevertStats, bool)> {
        let children_pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_block_items e WHERE e.intent_key=$1 AND e.block_hash=$2 AND e.kind='descendant' AND NOT EXISTS(SELECT 1 FROM tn10_live_recovery_blocks b WHERE b.intent_key=e.intent_key AND b.block_hash=e.item AND b.reverted))")
            .bind(&self.intent_key).bind(hash).fetch_one(&mut **tx).await?;
        ensure!(
            !children_pending,
            RecoveryReplanRequired("chunked descendant is not removed")
        );
        // Discovery runs behind the canonical writer fence. Rechecking the
        // entire footprint on every transaction would make each page scale
        // with the original block. Per-item dependencies are checked below;
        // the final page proves no indexed effects remain before block delete.
        if let Some(id) = self.chunked_next_tx(tx, hash).await? {
            ensure!(
                requested == [hex::encode(&id)],
                RecoveryReplanRequired("chunked removal page changed")
            );
            let bodies_staged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_transactions WHERE intent_key=$1 AND txid=$2)")
                .bind(&self.intent_key).bind(&id).fetch_one(&mut **tx).await?;
            ensure!(bodies_staged, "chunked removal has no pinned source body");
            let stats = writer
                .revert_block_effects_tx(tx, hash, Some(std::slice::from_ref(&id)), false)
                .await?;
            sqlx::query("UPDATE tn10_live_recovery_block_items SET removed=TRUE WHERE intent_key=$1 AND block_hash=$2 AND kind='transaction' AND item=$3")
                .bind(&self.intent_key).bind(hash).bind(&id).execute(&mut **tx).await?;
            return Ok((stats, false));
        }
        ensure!(
            requested.is_empty(),
            RecoveryReplanRequired("chunked final page changed")
        );
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_block_items WHERE intent_key=$1 AND block_hash=$2 AND kind='transaction' AND NOT removed)")
            .bind(&self.intent_key).bind(hash).fetch_one(&mut **tx).await?;
        ensure!(
            !pending,
            RecoveryReplanRequired("chunked transaction dependency cycle or missing descendant")
        );
        let residual: bool =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT EXISTS({})", IDS.replace(" UNION SELECT", " UNION ALL SELECT"))))
                .bind(hash)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(
            !residual,
            RecoveryReplanRequired("chunked block still has indexed effects")
        );
        Ok((
            writer
                .revert_block_effects_tx(tx, hash, Some(&[]), true)
                .await?,
            true,
        ))
    }
}
