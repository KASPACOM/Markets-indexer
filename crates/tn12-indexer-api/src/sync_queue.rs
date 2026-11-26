//! Durable receipt of authenticated direct-sync requests. Queue writes never
//! mutate canonical data. The consumer uses the normal persister and read fence.
use super::{AppState, Response, StatusCode};
use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::time::Duration;

/// An internal result marker, never inferred from HTTP 202 alone.
#[derive(Clone)]
pub(super) struct Applied;

pub(super) fn applied(mut response: Response) -> Response {
    response.extensions_mut().insert(Applied);
    response
}

pub(super) async fn observe(pool: &PgPool) -> Option<(i64, bool)> {
    tokio::time::timeout(Duration::from_millis(250), sqlx::query_as(
        "SELECT generation, (EXISTS(SELECT 1 FROM tn10_live_recovery_plans WHERE exclusive_writes) OR EXISTS(SELECT 1 FROM tn10_live_event_fences)) FROM tn10_recovery_read_fence WHERE singleton"
    ).fetch_one(pool)).await.ok()?.ok()
}

pub(super) async fn enqueue(pool: &PgPool, network: &str, txid: &str, force: bool) -> Result<()> {
    let mut tx = pool.begin().await?;
    limits(&mut tx).await?;
    sqlx::query("INSERT INTO tn10_direct_sync_requests(network,txid,force) VALUES($1,decode($2,'hex'),$3) ON CONFLICT(network,txid) DO UPDATE SET force=tn10_direct_sync_requests.force OR EXCLUDED.force, revision=tn10_direct_sync_requests.revision + CASE WHEN EXCLUDED.force AND NOT tn10_direct_sync_requests.force THEN 1 ELSE 0 END")
        .bind(network).bind(txid).bind(force).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Summary {
    pending: i64,
    oldest_request_age_ms: Option<i64>,
    retrying: i64,
}

pub(super) async fn summary(pool: &PgPool, network: &str) -> Result<Summary> {
    let (pending,age,retrying):(i64,Option<i64>,i64)=sqlx::query_as("SELECT count(*), greatest((extract(epoch FROM clock_timestamp())*1000)::bigint-min(requested_at_ms),0),count(*) FILTER(WHERE last_failure IS NOT NULL) FROM tn10_direct_sync_requests WHERE network=$1")
        .bind(network).fetch_one(pool).await?;
    Ok(Summary {
        pending,
        oldest_request_age_ms: age,
        retrying,
    })
}

pub(super) async fn write_metrics(pool: &PgPool, network: &str, output: &mut String) {
    use std::fmt::Write;
    if let Ok(s) = summary(pool, network).await {
        let _=writeln!(output,"tn10_indexer_direct_sync_pending {}\ntn10_indexer_direct_sync_oldest_age_seconds {}\ntn10_indexer_direct_sync_retrying {}",s.pending,s.oldest_request_age_ms.unwrap_or(0) as f64/1000.0,s.retrying);
    }
}

struct Claim {
    txid: String,
    token: String,
    revision: i64,
    force: bool,
}

async fn claim(
    pool: &PgPool,
    network: &str,
) -> Result<Option<(Claim, sqlx::pool::PoolConnection<sqlx::Postgres>)>> {
    let mut connection = pool.acquire().await?;
    connection.close_on_drop();
    sqlx::query("SET statement_timeout='2s'")
        .execute(&mut *connection)
        .await?;
    sqlx::query("SET lock_timeout='350ms'")
        .execute(&mut *connection)
        .await?;
    // Session ownership, rather than a long lease timer, decides whether a
    // crashed request can resume. Scan a bounded lookahead past active peers.
    let ids:Vec<String>=sqlx::query_scalar("SELECT encode(txid,'hex') FROM tn10_direct_sync_requests WHERE network=$1 AND next_attempt_at_ms <= (extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY next_attempt_at_ms,requested_at_ms LIMIT 32")
        .bind(network).fetch_all(&mut *connection).await?;
    for id in ids {
        let key = format!("{network}:{id}");
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(1415074641,hashtext($1))")
                .bind(&key)
                .fetch_one(&mut *connection)
                .await?;
        if !locked {
            continue;
        }
        let row=sqlx::query("UPDATE tn10_direct_sync_requests SET lease_token=gen_random_uuid(),lease_until_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint+300000,attempts=attempts+1 WHERE network=$1 AND txid=decode($2,'hex') AND next_attempt_at_ms <= (extract(epoch FROM clock_timestamp())*1000)::bigint RETURNING encode(txid,'hex') AS txid,lease_token::text AS token,revision,force")
            .bind(network).bind(&id).fetch_optional(&mut *connection).await?;
        if let Some(r) = row {
            let claim = Claim {
                txid: r.get("txid"),
                token: r.get("token"),
                revision: r.get("revision"),
                force: r.get("force"),
            };
            return Ok(Some((claim, connection)));
        }
        sqlx::query("SELECT pg_advisory_unlock(1415074641,hashtext($1))")
            .bind(&key)
            .execute(&mut *connection)
            .await?;
    }
    connection.close().await?;
    Ok(None)
}

async fn limits(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='350ms'")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn retry(pool: &PgPool, network: &str, claim: &Claim, reason: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    limits(&mut tx).await?;
    sqlx::query("UPDATE tn10_direct_sync_requests SET lease_token=NULL,lease_until_ms=0,last_failure=$4,next_attempt_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint+LEAST(60000,2000*LEAST(attempts,30)) WHERE network=$1 AND txid=decode($2,'hex') AND lease_token=$3::uuid")
        .bind(network).bind(&claim.txid).bind(&claim.token).bind(reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// A lost finish response is safe: deletion commits only after successful
/// ingestion, under the same canonical generation and writer serialization.
async fn finish(pool: &PgPool, network: &str, claim: &Claim, generation: i64) -> Result<bool> {
    let mut tx = pool.begin().await?;
    limits(&mut tx).await?;
    // Same canonical lock as PgPersister; do not race a recovery handoff.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x544e31324b434332_i64)
        .execute(&mut *tx)
        .await?;
    let clear: bool=sqlx::query_scalar("SELECT generation=$1 AND NOT EXISTS(SELECT 1 FROM tn10_live_recovery_plans WHERE exclusive_writes) AND NOT EXISTS(SELECT 1 FROM tn10_live_event_fences) FROM tn10_recovery_read_fence WHERE singleton")
        .bind(generation).fetch_one(&mut *tx).await?;
    let removed = if clear {
        sqlx::query("DELETE FROM tn10_direct_sync_requests WHERE network=$1 AND txid=decode($2,'hex') AND lease_token=$3::uuid AND revision=$4")
            .bind(network).bind(&claim.txid).bind(&claim.token).bind(claim.revision).execute(&mut *tx).await?.rows_affected()==1
    } else {
        false
    };
    tx.commit().await?;
    Ok(removed)
}

pub(super) async fn drain_one(state: &AppState) -> Result<bool> {
    let writer = state
        .persister
        .as_ref()
        .context("sync consumer has no writer")?;
    let pool = writer.pool();
    let Some((generation, false)) = observe(pool).await else {
        return Ok(false);
    };
    let Some((claim, mut connection)) = claim(pool, &state.network_id).await? else {
        return Ok(false);
    };
    let result = consume_claim(state, &claim, generation).await;
    let released =
        sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(1415074641,hashtext($1))")
            .bind(format!("{}:{}", state.network_id, claim.txid))
            .fetch_one(&mut *connection)
            .await;
    let closed = connection.close().await;
    // Never strand a session lock in the pool, including on failed consumption.
    let consumed = result?;
    anyhow::ensure!(released?, "sync request ownership was lost");
    closed?;
    Ok(consumed)
}

async fn consume_claim(state: &AppState, claim: &Claim, generation: i64) -> Result<bool> {
    let pool = state
        .persister
        .as_ref()
        .context("sync consumer has no writer")?
        .pool();
    if observe(pool).await != Some((generation, false)) {
        retry(
            pool,
            &state.network_id,
            claim,
            "canonical_recovery_in_progress",
        )
        .await?;
        return Ok(false);
    }
    // Queued work must re-fetch explicit, uncached acceptance evidence. Normal
    // online sync retains its existing lookup/fallback behavior.
    let response = super::tx_sync_now(state, &claim.txid, claim.force, true).await;
    let persisted = response.extensions().get::<Applied>().is_some();
    let status = response.status();
    drop(response);
    if persisted && finish(pool, &state.network_id, claim, generation).await? {
        return Ok(true);
    }
    let reason = if persisted {
        "canonical_generation_or_request_changed"
    } else if status == StatusCode::ACCEPTED {
        "awaiting_source_or_decoding"
    } else {
        "ingestion_failed"
    };
    retry(pool, &state.network_id, claim, reason).await?;
    Ok(true)
}

pub(super) fn spawn(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    state.persister.as_ref()?;
    Some(tokio::spawn(async move {
        loop {
            let pause = match drain_one(&state).await {
                Ok(true) => Duration::from_millis(25),
                Ok(false) => Duration::from_millis(500),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "direct sync queue retained work after consumer error"
                    );
                    Duration::from_secs(5)
                }
            };
            tokio::time::sleep(pause).await;
        }
    }))
}
