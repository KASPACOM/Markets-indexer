//! V2 effects share the existing decoder implementation and commit boundary.
use super::*;
use sqlx::Row;

impl PgPersister {
    /// Read the durable step under ownership and atomically commit its effects,
    /// trigger-captured preimages and exact progress. A replayed cursor is a no-op.
    pub async fn apply_shadow_step(&self, epoch: i64, plan: i64, cursor: i64) -> Result<bool> {
        let mut conn = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut conn).await?;
        let stored: i64 = sqlx::query_scalar("SELECT cursor FROM shadow_v2.fence($1,$2)")
            .bind(epoch)
            .bind(plan)
            .fetch_one(&mut *conn)
            .await?;
        if stored > cursor {
            conn.rollback().await?;
            return Ok(false);
        }
        anyhow::ensure!(stored == cursor, "shadow step is out of order");
        self.acquire_persist_writer_lock(&mut conn).await?;
        let step = sqlx::query(
            "SELECT kind,evidence FROM shadow_v2.steps WHERE plan_id=$1 AND ordinal=$2",
        )
        .bind(plan)
        .bind(cursor)
        .fetch_one(&mut *conn)
        .await?;
        let evidence: Value = step.get("evidence");
        match step.get::<String, _>("kind").as_str() {
            "apply" => {
                let body: RestTransaction = serde_json::from_value(evidence)?;
                anyhow::ensure!(
                    body.is_accepted
                        && body.accepting_block_hash.is_some()
                        && body.accepting_block_blue_score.is_some(),
                    "shadow apply lacks acceptance evidence"
                );
                sqlx::query("SAVEPOINT shadow_decode")
                    .execute(&mut *conn)
                    .await?;
                let result = self
                    .persist_tx_effects(&mut conn, &body, None, false, None)
                    .await;
                match result {
                    Err(error)
                        if error
                            .downcast_ref::<tn12_indexer_decoder::InterpretationFailure>()
                            .is_some()
                            && error
                                .downcast_ref::<tn12_indexer_decoder::IntegrityFailure>()
                                .is_none() =>
                    {
                        sqlx::query("ROLLBACK TO SAVEPOINT shadow_decode")
                            .execute(&mut *conn)
                            .await?;
                        self.persist_tx_effects(
                            &mut conn,
                            &body,
                            None,
                            false,
                            Some(&format!("{error:#}")),
                        )
                        .await?;
                    }
                    other => {
                        other?;
                    }
                }
                sqlx::query("RELEASE SAVEPOINT shadow_decode")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("INSERT INTO shadow_v2.acceptance_events(plan_id,cursor,kind,txid,block_hash) VALUES($1,$2,'accepted',$3,$4)")
                    .bind(plan).bind(cursor).bind(hex::decode(&body.transaction_id)?)
                    .bind(hex::decode(body.accepting_block_hash.as_deref().unwrap())?).execute(&mut *conn).await?;
            }
            "remove" => {
                let hash = hex::decode(evidence["hash"].as_str().context("removal lacks hash")?)?;
                let seed: Vec<u8> =
                    sqlx::query_scalar("SELECT history_start_hash FROM shadow_v2.control")
                        .fetch_one(&mut *conn)
                        .await?;
                anyhow::ensure!(
                    hash != seed,
                    "reorg crosses seed boundary; verified reseed required"
                );
                let known: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM blocks WHERE hash=$1 AND is_chain_block)",
                )
                .bind(&hash)
                .fetch_one(&mut *conn)
                .await?;
                anyhow::ensure!(known, "removal lacks retained canonical block");
                Self::record_rest_removals(&mut conn, std::slice::from_ref(&hash)).await?;
                Self::invalidate_historical_acceptance_targets(
                    &mut conn,
                    std::slice::from_ref(&hash),
                )
                .await?;
                self.revert_block_tx(&mut conn, &hash).await?;
                Self::retire_removed_acceptance_replacements(
                    &mut conn,
                    std::slice::from_ref(&hash),
                )
                .await?;
                sqlx::query("INSERT INTO shadow_v2.acceptance_events(plan_id,cursor,kind,block_hash) VALUES($1,$2,'removed',$3)")
                    .bind(plan).bind(cursor).bind(&hash).execute(&mut *conn).await?;
            }
            "anchor" => {
                sqlx::query("INSERT INTO blocks(hash,blue_score,timestamp_ms,is_chain_block,indexed_at_ms,daa_score,parent_hashes) VALUES($1,$2,$3,true,$3,$4,$5) ON CONFLICT(hash) DO UPDATE SET is_chain_block=true")
                    .bind(hex::decode(evidence["hash"].as_str().context("anchor lacks hash")?)?)
                    .bind(evidence["score"].as_i64().context("anchor score out of range")?)
                    .bind(evidence["time"].as_i64().context("anchor time out of range")?)
                    .bind(evidence["daa"].as_i64().context("anchor DAA out of range")?)
                    .bind(evidence["parents"].as_array().context("anchor parents missing")?.iter().map(|v|hex::decode(v.as_str().unwrap_or("invalid"))).collect::<std::result::Result<Vec<_>,_>>()?)
                    .execute(&mut *conn).await?;
            }
            _ => anyhow::bail!("unknown shadow step"),
        }
        sqlx::query("SELECT shadow_v2.finish_step($1,$2,$3)")
            .bind(epoch)
            .bind(plan)
            .bind(cursor)
            .execute(&mut *conn)
            .await?;
        conn.commit().await?;
        Ok(true)
    }
}
