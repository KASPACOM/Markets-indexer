//! Durable, fenced discovery for a retained live recovery intent.
//! A plan never grants permission to acknowledge its original journal.
use super::{
    recovery_impact, PgPersister, RecoveryBlockImpact, RecoveryReplanRequired, RevertStats,
};
use anyhow::{ensure, Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tn12_indexer_core::RestTransaction;

const LEASE_MS: i64 = 30_000;
const MAX_PAGE_BLOCKS: usize = 32;
const MAX_PAGE_TRANSACTIONS: usize = 32;
const MAX_SOURCE_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct PagedRecoveryOwner {
    pub intent_key: String,
    pub intent_sha256: Vec<u8>,
    pub token: String,
    pub generation: i64,
}

#[derive(Debug)]
pub enum RecoveryReplayPage {
    /// Durable preparation or release work remains; this is not end-of-replay.
    Preparing,
    Ready(Vec<RestTransaction>),
}

#[derive(Clone, Debug)]
pub struct StagedRecoveryBlock {
    pub impact: RecoveryBlockImpact,
    pub blue_score: i64,
    pub source_is_chain_block: bool,
}

pub(super) fn decode_hash(hash: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hash).context("decode recovery identity")?;
    ensure!(bytes.len() == 32, "recovery identity must be 32 bytes");
    Ok(bytes)
}

fn canonical_hashes(values: &[String]) -> Result<Vec<String>> {
    let mut hashes = values
        .iter()
        .map(|hash| decode_hash(hash).map(hex::encode))
        .collect::<Result<Vec<_>>>()?;
    hashes.sort_unstable();
    hashes.dedup();
    ensure!(hashes.len() == values.len(), "duplicate recovery identity");
    Ok(hashes)
}

pub(super) async fn lock_intent_and_owner(
    tx: &mut Transaction<'_, Postgres>,
    owner: &PagedRecoveryOwner,
) -> Result<()> {
    let digest: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT value_sha256 FROM indexer_state WHERE key=$1 FOR SHARE",
    )
    .bind(&owner.intent_key)
    .fetch_optional(&mut **tx)
    .await?;
    ensure!(
        digest.as_deref() == Some(owner.intent_sha256.as_slice()),
        "retained recovery intent changed or disappeared"
    );
    let now = chrono::Utc::now().timestamp_millis();
    let updated = sqlx::query(
        "UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=$5,updated_at_ms=$6 \
         WHERE intent_key=$1 AND intent_sha256=$2 AND owner_token=$3::uuid \
           AND generation=$4 AND lease_expires_at_ms>$6",
    )
    .bind(&owner.intent_key)
    .bind(&owner.intent_sha256)
    .bind(&owner.token)
    .bind(owner.generation)
    .bind(now + LEASE_MS)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    ensure!(
        updated.rows_affected() == 1,
        "paged recovery owner lost its lease"
    );
    Ok(())
}

impl PagedRecoveryOwner {
    pub async fn plan_exists(pool: &PgPool, intent_key: &str) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_plans WHERE intent_key=$1)",
        )
        .bind(intent_key)
        .fetch_one(pool)
        .await?)
    }

    /// Called under the writer lock, before persisting a canonical replay body.
    /// The staged source body is immutable for this intent and is checked again
    /// inside the same transaction as the eventual replay checkpoint.
    pub(super) async fn prepare_replay(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        body: &RestTransaction,
    ) -> Result<bool> {
        lock_intent_and_owner(tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(phase == "replay", "recovery is not in replay phase");
        let id = decode_hash(&body.transaction_id)?;
        let row = sqlx::query(
            "SELECT source_sha256=pg_catalog.sha256($3::jsonb::text::bytea) AS same,replayed \
             FROM tn10_live_recovery_transactions \
             WHERE intent_key=$1 AND txid=$2 FOR UPDATE",
        )
        .bind(&self.intent_key)
        .bind(id)
        .bind(body.recovery_identity())
        .fetch_one(&mut **tx)
        .await?;
        ensure!(
            row.try_get::<bool, _>("same")?,
            "canonical replay body differs from staged source evidence"
        );
        ensure!(body.is_accepted, "replay body is not accepted by source");
        Ok(!row.try_get::<bool, _>("replayed")?)
    }

    /// Persist the checkpoint with the transaction, never after its commit.
    pub(super) async fn checkpoint_replay(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        body: &RestTransaction,
    ) -> Result<()> {
        let id = decode_hash(&body.transaction_id)?;
        let updated = sqlx::query(
            "UPDATE tn10_live_recovery_transactions SET replayed=TRUE \
             WHERE intent_key=$1 AND txid=$2 AND NOT replayed",
        )
        .bind(&self.intent_key)
        .bind(id)
        .execute(&mut **tx)
        .await?;
        ensure!(updated.rows_affected() == 1, "replay checkpoint changed");
        sqlx::query(
            "UPDATE tn10_live_recovery_plans \
             SET replayed_transactions=replayed_transactions+1 WHERE intent_key=$1",
        )
        .bind(&self.intent_key)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Prepare a bounded page of derived dependency counts. All staged parents
    /// are known in replay phase; the owner lock serializes initialization with
    /// checkpoints. A crash resumes NULL rows without touching canonical data.
    pub async fn prepare_replay_page(&self, pool: &PgPool) -> Result<bool> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(phase == "replay", "recovery is not in replay phase");
        sqlx::query("SET LOCAL statement_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        let prepared = sqlx::query(
            "WITH page AS MATERIALIZED ( \
               SELECT txid, ARRAY(SELECT DISTINCT decode(input->>'previous_outpoint_hash','hex') \
                 FROM jsonb_array_elements(source_body->'inputs') input) AS parents \
               FROM tn10_live_recovery_transactions \
               WHERE intent_key=$1 AND replay_blockers IS NULL ORDER BY txid LIMIT $2 \
             ) , edges AS ( \
               INSERT INTO tn10_recovery_replay_edges(intent_key,parent_txid,child_txid) \
               SELECT $1,unnest(parents),txid FROM page ON CONFLICT DO NOTHING \
             ) UPDATE tn10_live_recovery_transactions target \
               SET replay_blockers=( \
                 SELECT count(*) FROM tn10_live_recovery_transactions parent \
                 WHERE parent.intent_key=$1 AND parent.txid=ANY(page.parents) AND NOT parent.replayed \
               ) FROM page WHERE target.intent_key=$1 AND target.txid=page.txid",
        ).bind(&self.intent_key).bind(MAX_PAGE_TRANSACTIONS as i64)
        .execute(&mut *tx).await?;
        if prepared.rows_affected() > 0 {
            sqlx::query("UPDATE tn10_live_recovery_plans SET last_durable_progress_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint,last_durable_checkpoint='replay-prepare-page' WHERE intent_key=$1")
                .bind(&self.intent_key).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(prepared.rows_affected() > 0)
    }

    /// Release at most 32 children of a committed parent. Recompute counts,
    /// rather than decrementing, so initialization, retries, and old-binary
    /// commits are idempotent. The cursor and child counts commit together.
    pub async fn release_replay_page(&self, pool: &PgPool) -> Result<bool> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        sqlx::query("SET LOCAL statement_timeout='10s'").execute(&mut *tx).await?;
        // Inspect at most 32 release cursors and return at most 32 child
        // updates total. This also batches independent chains and leaf cleanup.
        let page: Vec<(Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
            "WITH releases AS MATERIALIZED ( \
               SELECT parent_txid,after_child FROM tn10_recovery_replay_releases \
               WHERE intent_key=$1 ORDER BY parent_txid LIMIT $2 FOR UPDATE \
             ) SELECT releases.parent_txid,edge.child_txid FROM releases \
             LEFT JOIN LATERAL (SELECT child_txid FROM tn10_recovery_replay_edges \
               WHERE intent_key=$1 AND parent_txid=releases.parent_txid \
                 AND child_txid>COALESCE(releases.after_child,''::bytea) \
               ORDER BY child_txid LIMIT $2) edge ON TRUE \
             ORDER BY releases.parent_txid,edge.child_txid LIMIT $2",
        ).bind(&self.intent_key).bind(MAX_PAGE_TRANSACTIONS as i64)
         .fetch_all(&mut *tx).await?;
        if page.is_empty() {
            tx.commit().await?;
            return Ok(false);
        }
        let children: Vec<Vec<u8>> = page.iter().filter_map(|(_,child)|child.clone()).collect();
        if !children.is_empty() {
            sqlx::query(
                "UPDATE tn10_live_recovery_transactions child SET replay_blockers=( \
                   SELECT count(*) FROM tn10_recovery_replay_edges edge \
                   JOIN tn10_live_recovery_transactions parent \
                     ON parent.intent_key=edge.intent_key AND parent.txid=edge.parent_txid \
                   WHERE edge.intent_key=$1 AND edge.child_txid=child.txid AND NOT parent.replayed \
                 ) WHERE child.intent_key=$1 AND child.txid=ANY($2) AND child.replay_blockers IS NOT NULL",
            ).bind(&self.intent_key).bind(&children).execute(&mut *tx).await?;
        }
        let mut cursors=std::collections::BTreeMap::new();
        for (parent,child) in page { cursors.insert(parent,child); }
        for (parent,last) in cursors {
            if let Some(last) = last {
                sqlx::query("UPDATE tn10_recovery_replay_releases SET after_child=$3 WHERE intent_key=$1 AND parent_txid=$2")
                    .bind(&self.intent_key).bind(&parent).bind(last).execute(&mut *tx).await?;
            } else {
                sqlx::query("DELETE FROM tn10_recovery_replay_releases WHERE intent_key=$1 AND parent_txid=$2")
                    .bind(&self.intent_key).bind(&parent).execute(&mut *tx).await?;
            }
        }
        sqlx::query("UPDATE tn10_live_recovery_plans SET last_durable_progress_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint,last_durable_checkpoint='replay-release-page' WHERE intent_key=$1")
            .bind(&self.intent_key).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// A replay row is read through the fenced plan after an uncertain commit.
    pub async fn pending_replay(&self, pool: &PgPool) -> Result<RecoveryReplayPage> {
        // Bound preparation to one page of each kind per invocation. Newly
        // ready children can replay while a large release backlog remains.
        self.prepare_replay_page(pool).await?;
        self.release_replay_page(pool).await?;
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT current.source_body FROM tn10_live_recovery_transactions current \
             WHERE current.intent_key=$1 AND NOT current.replayed \
               AND (current.source_body->>'is_accepted')::boolean IS TRUE \
               AND current.replay_blockers=0 \
             ORDER BY current.txid LIMIT $2",
        )
        .bind(&self.intent_key)
        .bind(MAX_PAGE_TRANSACTIONS as i64)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            let preparing: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_transactions WHERE intent_key=$1 AND replay_blockers IS NULL) \
                 OR EXISTS(SELECT 1 FROM tn10_recovery_replay_releases WHERE intent_key=$1)",
            ).bind(&self.intent_key).fetch_one(&mut *tx).await?;
            if preparing {
                tx.commit().await?;
                return Ok(RecoveryReplayPage::Preparing);
            }
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM tn10_live_recovery_transactions \
                 WHERE intent_key=$1 AND NOT replayed \
                   AND (source_body->>'is_accepted')::boolean IS TRUE",
            )
            .bind(&self.intent_key)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(waiting == 0, "recovery replay dependencies cannot advance");
        }
        tx.commit().await?;
        Ok(RecoveryReplayPage::Ready(rows.into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<_>, _>>()?))
    }

    pub async fn pending_rejected(&self, pool: &PgPool) -> Result<Vec<RestTransaction>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT source_body FROM tn10_live_recovery_transactions \
             WHERE intent_key=$1 AND NOT verified_rejected \
               AND (source_body->>'is_accepted')::boolean IS FALSE \
             ORDER BY txid LIMIT $2",
        )
        .bind(&self.intent_key)
        .bind(MAX_PAGE_TRANSACTIONS as i64)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub async fn finish_removal(&self, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tn10_live_recovery_blocks \
             WHERE intent_key=$1 AND NOT reverted",
        )
        .bind(&self.intent_key)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(remaining == 0, "recovery block removals are incomplete");
        let updated = sqlx::query(
            "UPDATE tn10_live_recovery_plans SET phase='replay' \
             WHERE intent_key=$1 AND phase='revert'",
        )
        .bind(&self.intent_key)
        .execute(&mut *tx)
        .await?;
        ensure!(updated.rows_affected() == 1, "recovery phase changed");
        // Discovery may have expanded after an earlier attempt. Recompute all
        // derived counts against the final staged closure before applying it.
        sqlx::query("UPDATE tn10_live_recovery_transactions SET replay_blockers=NULL WHERE intent_key=$1 AND replay_blockers IS NOT NULL")
            .bind(&self.intent_key).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The caller must obtain a fresh source rejection for this transaction.
    /// Rejections do not run through the accepted-transaction persister.
    pub async fn verify_rejected(&self, pool: &PgPool, body: &RestTransaction) -> Result<()> {
        ensure!(
            !body.is_accepted,
            "source accepted a rejected recovery body"
        );
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(phase == "replay", "recovery is not in replay phase");
        let id = decode_hash(&body.transaction_id)?;
        let row = sqlx::query(
            "SELECT source_sha256=pg_catalog.sha256($3::jsonb::text::bytea) AS same,verified_rejected \
             FROM tn10_live_recovery_transactions \
             WHERE intent_key=$1 AND txid=$2 FOR UPDATE",
        )
        .bind(&self.intent_key)
        .bind(&id)
        .bind(body.recovery_identity())
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            row.try_get::<bool, _>("same")?,
            "source rejection differs from staged evidence"
        );
        if !row.try_get::<bool, _>("verified_rejected")? {
            sqlx::query(
                "UPDATE tn10_live_recovery_transactions SET verified_rejected=TRUE \
                 WHERE intent_key=$1 AND txid=$2",
            )
            .bind(&self.intent_key)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn finish_replay(&self, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tn10_live_recovery_transactions \
             WHERE intent_key=$1 AND NOT replayed AND NOT verified_rejected",
        )
        .bind(&self.intent_key)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(remaining == 0, "recovery transaction replay is incomplete");
        let updated = sqlx::query(
            "UPDATE tn10_live_recovery_plans SET phase='verify' \
             WHERE intent_key=$1 AND phase='replay'",
        )
        .bind(&self.intent_key)
        .execute(&mut *tx)
        .await?;
        ensure!(updated.rows_affected() == 1, "recovery phase changed");
        tx.commit().await?;
        Ok(())
    }

    pub async fn verification_blocks(
        &self,
        pool: &PgPool,
        after: Option<&str>,
    ) -> Result<Vec<StagedRecoveryBlock>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            phase == "verify" || phase == "complete",
            "recovery is not in verification phase"
        );
        let cursor = after.map(decode_hash).transpose()?;
        let rows = sqlx::query(
            "SELECT block_hash,blue_score,transaction_ids,descendants,source_is_chain_block,reverted \
             FROM tn10_live_recovery_blocks \
             WHERE intent_key=$1 AND ($2::bytea IS NULL OR block_hash>$2) \
             ORDER BY block_hash LIMIT $3",
        )
        .bind(&self.intent_key)
        .bind(cursor)
        .bind(MAX_PAGE_BLOCKS as i64)
        .fetch_all(&mut *tx)
        .await?;
        let result = rows
            .into_iter()
            .map(|row| {
                ensure!(
                    row.try_get::<bool, _>("reverted")?,
                    "recovery block was not removed"
                );
                Ok(StagedRecoveryBlock {
                    impact: RecoveryBlockImpact {
                        block_hash: hex::encode(row.try_get::<Vec<u8>, _>("block_hash")?),
                        transaction_ids: serde_json::from_value(row.try_get("transaction_ids")?)?,
                        descendants: serde_json::from_value(row.try_get("descendants")?)?,
                    },
                    blue_score: row.try_get("blue_score")?,
                    source_is_chain_block: row.try_get("source_is_chain_block")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn verification_transactions(
        &self,
        pool: &PgPool,
        after: Option<&str>,
    ) -> Result<Vec<RestTransaction>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            phase == "verify" || phase == "complete",
            "recovery is not in verification phase"
        );
        let cursor = after.map(decode_hash).transpose()?;
        let rows = sqlx::query(
            "SELECT source_body,replayed,verified_rejected \
             FROM tn10_live_recovery_transactions \
             WHERE intent_key=$1 AND ($2::bytea IS NULL OR txid>$2) \
             ORDER BY txid LIMIT $3",
        )
        .bind(&self.intent_key)
        .bind(cursor)
        .bind(MAX_PAGE_TRANSACTIONS as i64)
        .fetch_all(&mut *tx)
        .await?;
        let result = rows
            .into_iter()
            .map(|row| {
                let body: RestTransaction = serde_json::from_value(row.try_get("source_body")?)?;
                ensure!(
                    if body.is_accepted {
                        row.try_get::<bool, _>("replayed")?
                    } else {
                        row.try_get::<bool, _>("verified_rejected")?
                    },
                    "recovery transaction was not committed"
                );
                Ok(body)
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(result)
    }

    /// The supervisor still owns acknowledgement of the original journal.
    /// A complete plan is reverified after restart until that acknowledgement
    /// succeeds; it never clears the journal on its own.
    pub async fn mark_complete(&self, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM tn10_live_recovery_blocks \
                    WHERE intent_key=$1 AND NOT reverted) \
                  + (SELECT count(*) FROM tn10_live_recovery_transactions \
                    WHERE intent_key=$1 AND NOT replayed AND NOT verified_rejected)",
        )
        .bind(&self.intent_key)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(remaining == 0, "paged recovery checkpoints are incomplete");
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            phase == "verify" || phase == "complete",
            "paged recovery has not verified source"
        );
        if phase == "verify" {
            sqlx::query("UPDATE tn10_live_recovery_plans SET phase='complete' WHERE intent_key=$1")
                .bind(&self.intent_key)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    /// Claim only a journal that still exists. An unexpired owner cannot be
    /// replaced; a successor must re-read committed plan progress first.
    pub async fn claim(pool: &PgPool, intent_key: &str, roots: &[String]) -> Result<Self> {
        ensure!(
            !intent_key.is_empty() && intent_key.len() <= 256,
            "invalid intent key"
        );
        let roots = canonical_hashes(roots)?;
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut *tx)
            .await?;
        let digest: Vec<u8> = sqlx::query_scalar(
            "SELECT value_sha256 FROM indexer_state WHERE key=$1 FOR SHARE",
        )
        .bind(intent_key)
        .fetch_one(&mut *tx)
        .await
        .context("claim paged recovery for retained intent")?;
        let now = chrono::Utc::now().timestamp_millis();
        let existing = sqlx::query(
            "SELECT intent_sha256,generation,lease_expires_at_ms,phase,roots \
             FROM tn10_live_recovery_plans WHERE intent_key=$1 FOR UPDATE",
        )
        .bind(intent_key)
        .fetch_optional(&mut *tx)
        .await?;
        let (token, generation): (String, i64) = if let Some(row) = existing {
            let previous_digest: Vec<u8> = row.try_get("intent_sha256")?;
            let expires: i64 = row.try_get("lease_expires_at_ms")?;
            ensure!(
                previous_digest == digest,
                "recovery plan belongs to a changed intent"
            );
            let stored_roots: Vec<String> = serde_json::from_value(row.try_get("roots")?)?;
            ensure!(
                roots.is_empty() || roots == stored_roots,
                "recovery roots changed after discovery began"
            );
            ensure!(expires <= now, RecoveryReplanRequired("another paged recovery owner is active"));
            let generation: i64 = row.try_get("generation")?;
            let generation = generation
                .checked_add(1)
                .context("recovery generation overflow")?;
            let token: String = sqlx::query_scalar(
                "UPDATE tn10_live_recovery_plans SET generation=$2,owner_token=gen_random_uuid(), \
                 lease_expires_at_ms=$3,updated_at_ms=$4 WHERE intent_key=$1 RETURNING owner_token::text",
            )
            .bind(intent_key)
            .bind(generation)
            .bind(now + LEASE_MS)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            (token, generation)
        } else {
            let token: String = sqlx::query_scalar(
                "INSERT INTO tn10_live_recovery_plans \
                 (intent_key,intent_sha256,roots,owner_token,lease_expires_at_ms,phase,updated_at_ms) \
                 VALUES($1,$2,$3,gen_random_uuid(),$4,'discover',$5) RETURNING owner_token::text",
            )
            .bind(intent_key)
            .bind(&digest)
            .bind(serde_json::to_value(&roots)?)
            .bind(now + LEASE_MS)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            for root in &roots {
                sqlx::query(
                    "INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) VALUES($1,$2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(intent_key)
                .bind(decode_hash(root)?)
                .execute(&mut *tx)
                .await?;
            }
            (token, 1)
        };
        tx.commit().await?;
        Ok(Self {
            intent_key: intent_key.to_owned(),
            intent_sha256: digest,
            token,
            generation,
        })
    }

    pub async fn roots(&self, pool: &PgPool) -> Result<Vec<String>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let roots: serde_json::Value =
            sqlx::query_scalar("SELECT roots FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(serde_json::from_value(roots)?)
    }

    pub async fn phase(&self, pool: &PgPool) -> Result<String> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(phase)
    }

    pub async fn heartbeat(&self, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn pending_blocks(&self, pool: &PgPool) -> Result<Vec<String>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let hashes: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT block_hash FROM tn10_live_recovery_frontier \
             WHERE intent_key=$1 AND NOT processed ORDER BY block_hash LIMIT $2",
        )
        .bind(&self.intent_key)
        .bind(MAX_PAGE_BLOCKS as i64)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(hashes.into_iter().map(hex::encode).collect())
    }

    /// Store a verified discovery page and its descendant frontier together.
    /// A repeated page is harmless; conflicting evidence fails closed.
    pub async fn stage_blocks(&self, pool: &PgPool, blocks: &[StagedRecoveryBlock]) -> Result<()> {
        ensure!(
            !blocks.is_empty() && blocks.len() <= MAX_PAGE_BLOCKS,
            "invalid recovery page"
        );
        ensure!(
            blocks
                .iter()
                .map(|block| block.impact.transaction_ids.len())
                .sum::<usize>()
                <= 256,
            "recovery page exceeds transaction safety limit"
        );
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let mut inserted = 0_i64;
        for block in blocks {
            ensure!(block.blue_score >= 0, "negative recovery score");
            ensure!(
                block.impact.transaction_ids.len() <= 256,
                "single recovery block exceeds the transaction safety limit"
            );
            let hash = decode_hash(&block.impact.block_hash)?;
            let on_frontier: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_frontier \
                 WHERE intent_key=$1 AND block_hash=$2)",
            )
            .bind(&self.intent_key)
            .bind(&hash)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                on_frontier,
                "discovery page contains a block outside its frontier"
            );
            let ids = serde_json::to_value(canonical_hashes(&block.impact.transaction_ids)?)?;
            let descendants = serde_json::to_value(canonical_hashes(&block.impact.descendants)?)?;
            let result = sqlx::query(
                "INSERT INTO tn10_live_recovery_blocks \
                 (intent_key,block_hash,blue_score,transaction_ids,descendants,source_is_chain_block) \
                 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            )
            .bind(&self.intent_key)
            .bind(&hash)
            .bind(block.blue_score)
            .bind(&ids)
            .bind(&descendants)
            .bind(block.source_is_chain_block)
            .execute(&mut *tx)
            .await?;
            inserted += result.rows_affected() as i64;
            if result.rows_affected() == 0 {
                let same: bool = sqlx::query_scalar(
                    "SELECT blue_score=$3 AND transaction_ids=$4 AND descendants=$5 \
                     AND source_is_chain_block=$6 FROM tn10_live_recovery_blocks \
                     WHERE intent_key=$1 AND block_hash=$2",
                )
                .bind(&self.intent_key)
                .bind(&hash)
                .bind(block.blue_score)
                .bind(&ids)
                .bind(&descendants)
                .bind(block.source_is_chain_block)
                .fetch_one(&mut *tx)
                .await?;
                ensure!(same, "staged recovery block evidence changed");
            }
            for child in &block.impact.descendants {
                sqlx::query(
                    "INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) VALUES($1,$2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&self.intent_key)
                .bind(decode_hash(child)?)
                .execute(&mut *tx)
                .await?;
            }
            for id in &block.impact.transaction_ids {
                sqlx::query(
                    "INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) VALUES($1,$2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&self.intent_key)
                .bind(decode_hash(id)?)
                .execute(&mut *tx)
                .await?;
            }
            let updated = sqlx::query(
                "UPDATE tn10_live_recovery_frontier SET processed=TRUE \
                 WHERE intent_key=$1 AND block_hash=$2 AND NOT processed",
            )
            .bind(&self.intent_key)
            .bind(&hash)
            .execute(&mut *tx)
            .await?;
            ensure!(updated.rows_affected() <= 1, "invalid recovery frontier");
        }
        sqlx::query(
            "UPDATE tn10_live_recovery_plans SET discovered_blocks=discovered_blocks+$2 \
             WHERE intent_key=$1",
        )
        .bind(&self.intent_key)
        .bind(inserted)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Include accepted intent transactions that are not in a removed block.
    /// They still need a pinned source body before any destructive step.
    pub async fn enqueue_transactions(&self, pool: &PgPool, txids: &[String]) -> Result<()> {
        ensure!(
            txids.len() <= MAX_PAGE_TRANSACTIONS,
            "transaction page is too large"
        );
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        for id in canonical_hashes(txids)? {
            sqlx::query(
                "INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) VALUES($1,$2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&self.intent_key)
            .bind(decode_hash(&id)?)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn pending_transactions(&self, pool: &PgPool) -> Result<Vec<String>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let ids: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT txid FROM tn10_live_recovery_tx_frontier \
             WHERE intent_key=$1 AND NOT processed ORDER BY txid LIMIT $2",
        )
        .bind(&self.intent_key)
        .bind(MAX_PAGE_TRANSACTIONS as i64)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ids.into_iter().map(hex::encode).collect())
    }

    /// Pin canonical or explicitly rejected source bodies in bounded pages.
    /// A changed body forces a new source plan; an identical retry is harmless.
    pub async fn stage_transactions(
        &self,
        pool: &PgPool,
        bodies: &[RestTransaction],
    ) -> Result<()> {
        ensure!(
            !bodies.is_empty() && bodies.len() <= MAX_PAGE_TRANSACTIONS,
            "invalid transaction discovery page"
        );
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        for body in bodies {
            let id = decode_hash(&body.transaction_id)?;
            ensure!(
                !body.is_accepted
                    || (body
                        .accepting_block_hash
                        .as_ref()
                        .is_some_and(|hash| decode_hash(hash).is_ok())
                        && body.accepting_block_blue_score.is_some()
                        && !body.outputs.is_empty()),
                "accepted recovery body is incomplete"
            );
            let raw = serde_json::to_vec(body)?;
            ensure!(
                raw.len() <= MAX_SOURCE_BODY_BYTES,
                "recovery source body is too large"
            );
            let source: serde_json::Value = serde_json::from_slice(&raw)?;
            let identity = body.recovery_identity();
            let on_frontier: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_tx_frontier \
                 WHERE intent_key=$1 AND txid=$2)",
            )
            .bind(&self.intent_key)
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(on_frontier, "transaction body is outside recovery frontier");
            let inserted = sqlx::query(
                "INSERT INTO tn10_live_recovery_transactions \
                 (intent_key,txid,source_body,source_sha256) \
                 VALUES($1,$2,$3,pg_catalog.sha256($4::jsonb::text::bytea)) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&self.intent_key)
            .bind(&id)
            .bind(&source)
            .bind(&identity)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                let same: bool = sqlx::query_scalar(
                    "SELECT source_sha256=pg_catalog.sha256($3::jsonb::text::bytea) \
                     FROM tn10_live_recovery_transactions WHERE intent_key=$1 AND txid=$2",
                )
                .bind(&self.intent_key)
                .bind(&id)
                .bind(&identity)
                .fetch_one(&mut *tx)
                .await?;
                ensure!(same, "staged recovery transaction evidence changed");
            }
            sqlx::query(
                "UPDATE tn10_live_recovery_tx_frontier SET processed=TRUE \
                 WHERE intent_key=$1 AND txid=$2",
            )
            .bind(&self.intent_key)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// No removal may begin until the complete indexed descendant frontier is
    /// staged. A restart reads this phase rather than trusting local memory.
    pub async fn finish_discovery(&self, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tn10_live_recovery_frontier WHERE intent_key=$1 AND NOT processed",
        )
        .bind(&self.intent_key)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(remaining == 0, "indexed descendant discovery is incomplete");
        let pending_transactions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tn10_live_recovery_tx_frontier WHERE intent_key=$1 AND NOT processed",
        )
        .bind(&self.intent_key)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            pending_transactions == 0,
            "recovery transaction bodies are incomplete"
        );
        sqlx::query("UPDATE tn10_live_recovery_plans SET phase='revert' WHERE intent_key=$1 AND phase='discover'")
            .bind(&self.intent_key).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Return only leaves whose descendants have already committed as removed.
    /// This query keeps the memory footprint independent of closure size.
    pub async fn ready_removals(&self, pool: &PgPool) -> Result<Vec<StagedRecoveryBlock>> {
        let mut tx = pool.begin().await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(phase == "revert", "recovery is not in removal phase");
        let rows = sqlx::query(
            "SELECT b.block_hash,b.blue_score,b.transaction_ids,b.descendants,b.source_is_chain_block,b.chunked \
             FROM tn10_live_recovery_blocks b \
             WHERE b.intent_key=$1 AND NOT b.reverted AND NOT EXISTS ( \
               SELECT 1 FROM jsonb_array_elements_text(b.descendants) child(hash) \
               WHERE NOT EXISTS (SELECT 1 FROM tn10_live_recovery_blocks c \
                 WHERE c.intent_key=b.intent_key AND c.block_hash=decode(child.hash,'hex') AND c.reverted)) \
             AND NOT EXISTS(SELECT 1 FROM tn10_live_recovery_block_items e WHERE e.intent_key=b.intent_key AND e.block_hash=b.block_hash AND e.kind='descendant' AND NOT EXISTS(SELECT 1 FROM tn10_live_recovery_blocks c WHERE c.intent_key=e.intent_key AND c.block_hash=e.item AND c.reverted)) \
             ORDER BY b.blue_score DESC,b.block_hash LIMIT $2",
        )
        .bind(&self.intent_key)
        .bind(MAX_PAGE_BLOCKS as i64)
        .fetch_all(&mut *tx)
        .await?;
        let mut blocks = Vec::new();
        for row in rows {
            let hash: Vec<u8> = row.try_get("block_hash")?;
            let chunked: bool = row.try_get("chunked")?;
            let ids: serde_json::Value = row.try_get("transaction_ids")?;
            let descendants: serde_json::Value = row.try_get("descendants")?;
            let transaction_ids = if chunked {
                self.chunked_next_tx(&mut tx, &hash).await?.into_iter().map(hex::encode).collect()
            } else {
                serde_json::from_value(ids)?
            };
            blocks.push(StagedRecoveryBlock {
                impact: RecoveryBlockImpact {
                    block_hash: hex::encode(hash),
                    transaction_ids,
                    descendants: serde_json::from_value(descendants)?,
                },
                blue_score: row.try_get("blue_score")?,
                source_is_chain_block: row.try_get("source_is_chain_block")?,
            });
        }
        if blocks.is_empty() {
            let remaining: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM tn10_live_recovery_blocks WHERE intent_key=$1 AND NOT reverted",
            )
            .bind(&self.intent_key)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                remaining == 0,
                "recovery removal dependency cycle or missing descendant"
            );
        }
        tx.commit().await?;
        Ok(blocks)
    }

    /// The removal and durable checkpoint share one writer-locked transaction.
    /// A lost commit response is resolved by reading `reverted` on restart.
    pub async fn revert_one(
        &self,
        writer: &PgPersister,
        block: &StagedRecoveryBlock,
    ) -> Result<RevertStats> {
        if self.prepare_removal_summaries(writer, block).await? {
            return Ok(RevertStats::default());
        }
        // Canonical recovery can already fence ordinary writes. Dropping
        // this transaction at 350ms can repeatedly undo the same valid removal
        // without ever committing its checkpoint. Keep PostgreSQL statement and
        // lock timeouts in revert_one_inner, and yield only after its outcome is
        // known. Interrupted/uncertain commits still reconcile via `reverted`.
        let result = match self.revert_one_inner(writer, block).await {
            Err(error) if super::recovery_removal_steps::removal_needs_reconciliation(&error) => {
                self.reconcile_failed_removal(writer, block, &error)
                    .await
                    .map(|()| RevertStats::default())
            }
            other => other,
        };
        tokio::task::yield_now().await;
        result
    }

    async fn revert_one_inner(
        &self,
        writer: &PgPersister,
        block: &StagedRecoveryBlock,
    ) -> Result<RevertStats> {
        let hash = decode_hash(&block.impact.block_hash)?;
        let mut tx = writer.pool.begin().await?;
        PgPersister::set_persist_query_limits(&mut tx).await?;
        sqlx::query("SET LOCAL jit=off").execute(&mut *tx).await?;
        writer.acquire_recovery_writer_lock(&mut tx, Some(self)).await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
                .bind(&self.intent_key)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(phase == "revert", "recovery phase changed before removal");
        let staged = sqlx::query(
            "SELECT transaction_ids,descendants,reverted,chunked FROM tn10_live_recovery_blocks \
             WHERE intent_key=$1 AND block_hash=$2 FOR UPDATE",
        )
        .bind(&self.intent_key)
        .bind(&hash)
        .fetch_one(&mut *tx)
        .await?;
        if staged.try_get::<bool, _>("chunked")? {
            if staged.try_get::<bool, _>("reverted")? {
                tx.commit().await?;
                return Ok(RevertStats::default());
            }
            let canonical: bool = sqlx::query_scalar("SELECT COALESCE((SELECT is_chain_block FROM blocks WHERE hash=$1),FALSE)")
                .bind(&hash).fetch_one(&mut *tx).await?;
            if canonical {
                PgPersister::invalidate_historical_acceptance_targets(&mut tx, std::slice::from_ref(&hash)).await?;
            }
            sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair','on',TRUE)")
                .execute(&mut *tx).await?;
            PgPersister::record_rest_removals(&mut tx, std::slice::from_ref(&hash)).await?;
            let (stats, complete) = self.revert_chunked_locked(writer, &mut tx, &hash, &block.impact.transaction_ids).await?;
            if complete {
                if canonical {
                    PgPersister::retire_removed_acceptance_replacements(&mut tx, std::slice::from_ref(&hash)).await?;
                }
                sqlx::query("UPDATE tn10_live_recovery_blocks SET reverted=TRUE WHERE intent_key=$1 AND block_hash=$2")
                    .bind(&self.intent_key).bind(&hash).execute(&mut *tx).await?;
                sqlx::query("UPDATE tn10_live_recovery_plans SET reverted_blocks=reverted_blocks+1 WHERE intent_key=$1")
                    .bind(&self.intent_key).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            return Ok(stats);
        }
        let ids: Vec<String> = serde_json::from_value(staged.try_get("transaction_ids")?)?;
        let children: Vec<String> = serde_json::from_value(staged.try_get("descendants")?)?;
        ensure!(
            ids == canonical_hashes(&block.impact.transaction_ids)?
                && children == canonical_hashes(&block.impact.descendants)?,
            "removal page differs from staged evidence"
        );
        if staged.try_get::<bool, _>("reverted")? {
            tx.commit().await?;
            return Ok(RevertStats::default());
        }
        let pending_children: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM jsonb_array_elements_text($2::jsonb) child(hash) \
             WHERE NOT EXISTS (SELECT 1 FROM tn10_live_recovery_blocks c \
               WHERE c.intent_key=$1 AND c.block_hash=decode(child.hash,'hex') AND c.reverted)",
        )
        .bind(&self.intent_key)
        .bind(serde_json::to_value(&children)?)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            pending_children == 0,
            RecoveryReplanRequired("indexed descendant is not removed")
        );
        let actual = recovery_impact::load(&mut tx, &block.impact.block_hash).await?;
        let actual_ids = canonical_hashes(&actual.transaction_ids)?;
        let actual_children = canonical_hashes(&actual.descendants)?;
        if actual_ids.iter().any(|id| !ids.contains(id))
            || actual_children
                .iter()
                .any(|child| !children.contains(child))
        {
            // Discovery reads may precede the recovery fence. Preserve all prior
            // evidence and discover the additional footprint before any removal.
            let mut expanded_ids = ids.clone();
            expanded_ids.extend(actual_ids);
            expanded_ids.sort_unstable();
            expanded_ids.dedup();
            let mut expanded_children = children.clone();
            expanded_children.extend(actual_children);
            expanded_children.sort_unstable();
            expanded_children.dedup();
            ensure!(
                expanded_ids.len() <= 256 && expanded_children.len() <= 256,
                RecoveryReplanRequired("expanded recovery footprint exceeds bounded discovery")
            );
            ensure!(
                !expanded_children.contains(&hex::encode(&hash)),
                RecoveryReplanRequired("expanded recovery footprint contains itself")
            );
            let reopened_child: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_blocks b \
                 JOIN jsonb_array_elements_text($2::jsonb) child(hash) \
                   ON b.block_hash=decode(child.hash,'hex') \
                 WHERE b.intent_key=$1 AND b.reverted)",
            )
            .bind(&self.intent_key)
            .bind(serde_json::to_value(&actual.descendants)?)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                !reopened_child,
                RecoveryReplanRequired("removed descendant has indexed effects again")
            );
            let ids_json = serde_json::to_value(&expanded_ids)?;
            let children_json = serde_json::to_value(&expanded_children)?;
            sqlx::query(
                "UPDATE tn10_live_recovery_blocks SET transaction_ids=$3,descendants=$4 \
                 WHERE intent_key=$1 AND block_hash=$2 AND NOT reverted",
            )
            .bind(&self.intent_key)
            .bind(&hash)
            .bind(&ids_json)
            .bind(&children_json)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) \
                 SELECT $1,decode(value,'hex') FROM jsonb_array_elements_text($2::jsonb) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&self.intent_key)
            .bind(&children_json)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) \
                 SELECT $1,decode(value,'hex') FROM jsonb_array_elements_text($2::jsonb) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&self.intent_key)
            .bind(&ids_json)
            .execute(&mut *tx)
            .await?;
            // Commit only metadata. Expiring this locked lease fences the old
            // owner and lets the supervisor immediately resume discovery.
            // Keep ordinary repair/direct writers fenced until verification;
            // otherwise they can keep expanding the closure during retries.
            sqlx::query(
                "UPDATE tn10_live_recovery_plans SET phase='discover',exclusive_writes=TRUE,lease_expires_at_ms=0 \
                 WHERE intent_key=$1",
            )
            .bind(&self.intent_key)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(RecoveryReplanRequired(
                "indexed recovery footprint expanded; discovery required",
            )
            .into());
        }
        let canonical: Option<bool> =
            sqlx::query_scalar("SELECT is_chain_block FROM blocks WHERE hash=$1")
                .bind(&hash)
                .fetch_optional(&mut *tx)
                .await?;
        if canonical == Some(true) {
            PgPersister::invalidate_historical_acceptance_targets(
                &mut tx,
                std::slice::from_ref(&hash),
            )
            .await?;
        }
        sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair','on',TRUE)")
            .execute(&mut *tx)
            .await?;
        PgPersister::record_rest_removals(&mut tx, std::slice::from_ref(&hash)).await?;
        let stats = writer.revert_block_tx(&mut tx, &hash).await?;
        if canonical == Some(true) {
            PgPersister::retire_removed_acceptance_replacements(
                &mut tx,
                std::slice::from_ref(&hash),
            )
            .await?;
        }
        sqlx::query("UPDATE tn10_live_recovery_blocks SET reverted=TRUE WHERE intent_key=$1 AND block_hash=$2")
            .bind(&self.intent_key).bind(&hash).execute(&mut *tx).await?;
        sqlx::query("UPDATE tn10_live_recovery_plans SET reverted_blocks=reverted_blocks+1 WHERE intent_key=$1")
            .bind(&self.intent_key).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(stats)
    }
}

impl PgPersister {
    pub fn paged_recovery_pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn rejected_recovery_tx_has_effect(&self, txid: &str) -> Result<bool> {
        let id = decode_hash(txid)?;
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM covenant_actions WHERE txid=$1) \
                 OR EXISTS(SELECT 1 FROM covenant_utxos WHERE txid=$1)",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?)
    }
}

#[cfg(test)]
#[path = "paged_recovery_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "replay_ready_tests.rs"]
mod replay_ready_tests;
