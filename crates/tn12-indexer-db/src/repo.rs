//! Read-side queries against the indexer's Postgres tables.
//!
//! The watcher binary writes here via `persist::PgPersister`; the API binary
//! reads via these functions so its HTTP routes serve live DB state instead of
//! the empty in-memory engine that comes up at startup.

use crate::{
    claim::{self, ClaimedDeployment},
    PgPool,
};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use sqlx::{
    postgres::PgRow, AssertSqlSafe, PgConnection, Postgres, QueryBuilder, Row, Transaction,
};
use std::collections::BTreeSet;
use std::future::Future;
use std::time::Instant;

const API_READ_LOCK_TIMEOUT: &str = "1s";
const HEALTH_STATEMENT_TIMEOUT: &str = "1500ms";
const REST_OBSERVATION_FRESH_MS: i64 = 15_000;
const LIVE_ACCEPTANCE_FRESH_MS: i64 = 60_000;
pub const REST_DB_MAX_LAG_BLOCKS: i64 = 3_000;
const COVENANT_LIST_STATEMENT_TIMEOUT: &str = "5s";
const KCC20_ORDERBOOK_STATEMENT_TIMEOUT: &str = "3s";
const KCC20_OWNER_ACTION_STATEMENT_TIMEOUT: &str = "3s";
const KCC20_ORDERBOOK_MAX_ROWS: usize = 5_000;
const KCC20_TRADE_SUMMARY_MAX_ROWS: usize = 1_000;
const KCC20_REPAIR_BATCH_LIMIT: i64 = 250;
const KCC20_MARKET_PROJECTION: &str = "market";
const KCC20_TOKEN_PAGE_PROJECTION: &str = "token_page";
const KCC20_ACTIVITY_FEED_PROJECTION: &str = "activity_feed";
const KCC20_OWNER_ORDERS_PROJECTION: &str = "owner_orders";
const KCC20_OWNER_PORTFOLIO_ASSETS_PROJECTION: &str = "owner_portfolio_assets";
const KCC20_OWNER_ACTION_HISTORY_PROJECTION: &str = "owner_action_history";
const KCC20_ACTIVITY_READ_STATEMENT_TIMEOUT: &str = "2s";
const KCC20_ACTIVITY_REFRESH_OVERLAP_MS: i64 = 60 * 60 * 1000;
const DEFAULT_KCC20_ACTIVITY_REFRESH_STATEMENT_TIMEOUT: &str = "60s";

#[derive(Debug, Clone)]
pub struct Kcc20ActivityFeedRefreshConfig {
    pub wait_for_lock: bool,
    pub target_dirty_id: Option<i64>,
    pub full_refresh_enabled: bool,
    pub statement_timeout: String,
}

impl Kcc20ActivityFeedRefreshConfig {
    pub fn request_path() -> Self {
        Self {
            wait_for_lock: false,
            target_dirty_id: None,
            full_refresh_enabled: true,
            statement_timeout: DEFAULT_KCC20_ACTIVITY_REFRESH_STATEMENT_TIMEOUT.to_string(),
        }
    }

    pub fn projector(
        target_dirty_id: i64,
        full_refresh_enabled: bool,
        statement_timeout: String,
    ) -> Self {
        Self {
            wait_for_lock: true,
            target_dirty_id: Some(target_dirty_id),
            full_refresh_enabled,
            statement_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kcc20ActivityFeedRefreshMode {
    ScopedTxids,
    RecentWindow,
    Full,
    DisabledFull,
    SkippedIrrelevant,
    SkippedLock,
    Clean,
}

#[derive(Debug, Clone, Copy)]
pub struct Kcc20ActivityFeedRefreshStats {
    pub target_dirty_id: i64,
    pub last_dirty_id: i64,
    pub dirty_rows: i64,
    pub activity_dirty_rows: i64,
    pub scoped_dirty_txids: i64,
    pub mode: Kcc20ActivityFeedRefreshMode,
    pub refresh_from_ms: i64,
    pub rows_deleted: u64,
    pub rows_inserted: u64,
    pub elapsed_ms: u64,
}

/// Placeholder inserted immediately after each KCC20 trade/activity query's
/// existing `sellIntoBidByOwnerSig` de-dupe guard; swapped for
/// [`KCC20_CROSS_MATCH_DEDUPE_GUARD`] via [`kcc20_trade_sql`] before the
/// query reaches Postgres. A literal occurrence of this token left
/// un-replaced is invalid SQL and will fail loudly rather than silently
/// double-count trades.
const KCC20_CROSS_MATCH_DEDUPE_GUARD_TOKEN: &str = "__KCC20_CROSS_MATCH_DEDUPE_GUARD__";
const KCC20_ACTIVITY_REFRESH_SCOPE_JOIN_TOKEN: &str = "__KCC20_ACTIVITY_REFRESH_SCOPE_JOIN__";
const KCC20_ACTIVITY_REFRESH_SCOPE_FILTER_TOKEN: &str = "__KCC20_ACTIVITY_REFRESH_SCOPE_FILTER__";

/// A single atomic KCC20 crossed-orderbook match spends one ask input and one
/// bid input in ONE transaction, but is decoded into two separate
/// `covenant_actions` rows (`crossAskSide` + `crossBidSide`). Without this
/// guard, every trade/volume/activity query that lists these entrypoints
/// counts a crossed match twice. Mirrors the existing
/// `sellIntoBidByOwnerSig`/`fillBidPartial` guard immediately above each
/// insertion point: `crossAskSide` is kept as the canonical row (its
/// maker/taker resolution mirrors `fillAskPartial`'s working path; the
/// `crossBidSide` row's own decoded_args lack the field `fillBidPartial`'s
/// resolution path relies on), `crossBidSide` is excluded. The `inputIndex`
/// cross-reference is the precise correlation (persist-time enrichment
/// merges each spend's own `inputIndex` into `decoded_args`); the
/// `buyerOutputIndex`/`fillAmount` match is a fallback for rows predating
/// that enrichment, matching the fallback style already used for the
/// `sellIntoBidByOwnerSig` pairing.
///
/// Call sites (keep in sync): `kcc20_trades`, `kcc20_trade_summaries`,
/// `refresh_kcc20_market_summaries`, `kcc20_token_stats`, `kcc20_candles`,
/// `refresh_kcc20_activity_feed_with_config`, `kcc20_activity_raw`.
///
/// Unlike the retroactive `kcc20_cross_match_trade_dedupe` migration (which
/// only deletes a historical row when EXACTLY ONE candidate match exists,
/// to avoid guessing at an ambiguous pairing), this live guard is a plain
/// `EXISTS`. That's intentionally fine here: a bid input's transaction
/// covenant-id is committed on-chain (`OpInputCovenantId` in
/// `kcc20-orderbook.sil`) and the current matcher only ever builds one
/// ask/bid pair per transaction (`kcc20-pskt-builder-engine.service.ts` in
/// `kcc20-backend`), so there is no reachable case today where a
/// `crossBidSide` row could match more than one `crossAskSide` candidate in
/// its own txid. If that ever changes (a future batched/swept crossed-match
/// builder), this guard should gain the same `COUNT(*) = 1` ambiguity check
/// the migration has -- an `EXISTS`-only guard would still make the correct
/// exclude/keep decision even with an ambiguous match (it excludes based on
/// "was this part of *some* genuine cross match", and the surviving row's
/// own decoded_args are self-contained), but treating it as safe by
/// construction relies on the current one-pair-per-tx invariant holding.
const KCC20_CROSS_MATCH_DEDUPE_GUARD: &str = r#"
              AND NOT (
                a.action = 'spend'
                AND a.entrypoint = 'crossBidSide'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions ask_fill
                  WHERE ask_fill.txid = a.txid
                    AND ask_fill.action = 'spend'
                    AND ask_fill.entrypoint = 'crossAskSide'
                    AND (
                      (
                        NULLIF(ask_fill.decoded_args->>'inputIndex', '') IS NOT NULL
                        AND NULLIF(a.decoded_args->>'inputIndex', '') IS NOT NULL
                        AND ask_fill.decoded_args->>'inputIndex' = a.decoded_args->>'askInputIndex'
                        AND a.decoded_args->>'inputIndex' = ask_fill.decoded_args->>'bidInputIndex'
                      )
                      OR (
                        NULLIF(ask_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                        AND NULLIF(ask_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                      )
                    )
                )
              )"#;

/// Interpolates [`KCC20_CROSS_MATCH_DEDUPE_GUARD`] into a KCC20 trade/activity
/// query template at its [`KCC20_CROSS_MATCH_DEDUPE_GUARD_TOKEN`] placeholder.
fn kcc20_trade_sql(template: &str) -> String {
    template.replace(
        KCC20_CROSS_MATCH_DEDUPE_GUARD_TOKEN,
        KCC20_CROSS_MATCH_DEDUPE_GUARD,
    )
}

fn kcc20_activity_refresh_sql(template: &str, scoped_only: bool) -> String {
    let template = kcc20_trade_sql(template);
    if scoped_only {
        template
            .replace(
                KCC20_ACTIVITY_REFRESH_SCOPE_JOIN_TOKEN,
                "JOIN pending_dirty refresh_scope ON refresh_scope.txid = a.txid",
            )
            .replace(KCC20_ACTIVITY_REFRESH_SCOPE_FILTER_TOKEN, "TRUE")
    } else {
        template
            .replace(KCC20_ACTIVITY_REFRESH_SCOPE_JOIN_TOKEN, "")
            .replace(
                KCC20_ACTIVITY_REFRESH_SCOPE_FILTER_TOKEN,
                r#"
                (
                    a.block_time_ms >= $1
                    OR EXISTS (
                        SELECT 1
                        FROM pending_dirty dirty
                        WHERE dirty.txid = a.txid
                    )
                )
                "#,
            )
    }
}

async fn set_local_query_limits(
    tx: &mut Transaction<'_, Postgres>,
    lock_timeout: &str,
    statement_timeout: &str,
) -> Result<()> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(statement_timeout)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn set_local_kcc20_orderbook_limits(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    set_local_query_limits(tx, API_READ_LOCK_TIMEOUT, KCC20_ORDERBOOK_STATEMENT_TIMEOUT).await?;
    sqlx::query("SELECT set_config('jit', 'off', true)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Smoke test that the DB connection is alive.
pub async fn ping(pool: &PgPool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT 1::BIGINT").fetch_one(pool).await?;
    Ok(row.0)
}

pub const KCC20_PROJECTION_DIRTY_CHANNEL: &str = "kcc20_projection_dirty";

const KCC20_PROJECTION_DIRTY_COMMIT_BARRIER_SQL: &str =
    "hashtextextended('tn12:kcc20_projection_dirty_commit_barrier', 0)";

pub async fn mark_kcc20_projection_dirty_tx(
    tx: &mut Transaction<'_, Postgres>,
    reason: &str,
    txid: Option<&[u8]>,
) -> Result<()> {
    sqlx::query_scalar::<_, i64>(
        r#"
        WITH commit_barrier AS MATERIALIZED (
            SELECT pg_advisory_xact_lock_shared(
                hashtextextended('tn12:kcc20_projection_dirty_commit_barrier', 0)
            )
        ), inserted AS (
            INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
            SELECT $1, $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
            FROM commit_barrier
            RETURNING id
        )
        SELECT MAX(id)::BIGINT, pg_notify($3, MAX(id)::TEXT)
        FROM inserted
        "#,
    )
    .bind(reason)
    .bind(txid)
    .bind(KCC20_PROJECTION_DIRTY_CHANNEL)
    .fetch_one(&mut **tx)
    .await?;
    Ok(())
}

pub async fn mark_kcc20_projection_dirty_txids_tx(
    tx: &mut Transaction<'_, Postgres>,
    reason: &str,
    txids: &[Vec<u8>],
) -> Result<()> {
    if txids.is_empty() {
        return Ok(());
    }

    sqlx::query_scalar::<_, i64>(
        r#"
        WITH commit_barrier AS MATERIALIZED (
            SELECT pg_advisory_xact_lock_shared(
                hashtextextended('tn12:kcc20_projection_dirty_commit_barrier', 0)
            )
        ), inserted AS (
            INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
            SELECT $1, pending.txid, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
            FROM (
                SELECT DISTINCT txid
                FROM UNNEST($2::BYTEA[]) AS input(txid)
            ) AS pending
            CROSS JOIN commit_barrier
            RETURNING id
        )
        SELECT MAX(id)::BIGINT, pg_notify($3, MAX(id)::TEXT)
        FROM inserted
        "#,
    )
    .bind(reason)
    .bind(txids)
    .bind(KCC20_PROJECTION_DIRTY_CHANNEL)
    .fetch_one(&mut **tx)
    .await?;
    Ok(())
}

pub async fn mark_kcc20_projection_dirty(
    pool: &PgPool,
    reason: &str,
    txid: Option<&[u8]>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    mark_kcc20_projection_dirty_tx(&mut tx, reason, txid).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn kcc20_projection_dirty_target_for(
    pool: &PgPool,
    projection_name: &str,
) -> Result<Option<i64>> {
    let latest_dirty_id = kcc20_projection_latest_dirty_id(pool).await?;
    kcc20_projection_dirty_target_for_through(pool, projection_name, latest_dirty_id).await
}

pub async fn kcc20_projection_latest_dirty_id(pool: &PgPool) -> Result<i64> {
    let latest_dirty_id =
        sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
            .fetch_one(pool)
            .await?;
    Ok(latest_dirty_id)
}

/// Capture a pass boundary after every dirty writer that allocated an earlier
/// sequence value has committed or rolled back.
pub async fn capture_kcc20_projection_pass_dirty_id(conn: &mut PgConnection) -> Result<i64> {
    let latest_dirty_id = sqlx::query_scalar(AssertSqlSafe(format!(
        r#"
        WITH commit_barrier AS MATERIALIZED (
            SELECT pg_advisory_xact_lock({KCC20_PROJECTION_DIRTY_COMMIT_BARRIER_SQL})
        )
        SELECT COALESCE(MAX(dirty.id), 0)::BIGINT
        FROM commit_barrier
        LEFT JOIN kcc20_projection_dirty dirty ON TRUE
        "#
    )))
    .fetch_one(conn)
    .await?;
    Ok(latest_dirty_id)
}

pub async fn kcc20_projection_dirty_target_for_through(
    pool: &PgPool,
    projection_name: &str,
    target_dirty_id: i64,
) -> Result<Option<i64>> {
    let target = sqlx::query_scalar(
        r#"
        WITH state AS (
            SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
            FROM kcc20_projection_state
            WHERE name = $1
        )
        SELECT CASE
            WHEN $2::BIGINT > COALESCE((SELECT last_dirty_id FROM state), 0)
            THEN $2::BIGINT
            ELSE NULL
        END
        "#,
    )
    .bind(projection_name)
    .bind(target_dirty_id)
    .fetch_one(pool)
    .await?;
    Ok(target)
}

pub async fn kcc20_activity_projection_dirty_target_for_through(
    pool: &PgPool,
    target_dirty_id: i64,
    max_distinct_txids: i64,
) -> Result<Option<i64>> {
    let target = sqlx::query_scalar(
        r#"
        WITH state AS (
            SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
            FROM kcc20_projection_state
            WHERE name = 'activity_feed'
        ), pending AS MATERIALIZED (
            SELECT id, txid
            FROM kcc20_projection_dirty
            WHERE id > COALESCE((SELECT last_dirty_id FROM state), 0)
              AND id <= $1::BIGINT
        ), first_scoped_occurrence AS (
            SELECT txid, MIN(id)::BIGINT AS first_id
            FROM pending
            WHERE txid IS NOT NULL
            GROUP BY txid
        ), overflow AS (
            SELECT first_id
            FROM first_scoped_occurrence
            ORDER BY first_id
            OFFSET $2::BIGINT
            LIMIT 1
        )
        SELECT MAX(id)::BIGINT
        FROM pending
        WHERE id < COALESCE((SELECT first_id FROM overflow), $1::BIGINT + 1)
        "#,
    )
    .bind(target_dirty_id)
    .bind(max_distinct_txids.max(1))
    .fetch_one(pool)
    .await?;
    Ok(target)
}

pub async fn mark_kcc20_projection_refreshed_for(
    pool: &PgPool,
    projection_name: &str,
    dirty_id: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO kcc20_projection_state (name, last_dirty_id, refreshed_at_ms)
        VALUES ($1, $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
        ON CONFLICT (name) DO UPDATE SET
            last_dirty_id = GREATEST(kcc20_projection_state.last_dirty_id, EXCLUDED.last_dirty_id),
            refreshed_at_ms = EXCLUDED.refreshed_at_ms
        "#,
    )
    .bind(projection_name)
    .bind(dirty_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn prune_kcc20_projection_dirty(pool: &PgPool, max_rows: i64) -> Result<u64> {
    let deleted = sqlx::query(
        r#"
        WITH projection_cutoff AS (
            SELECT MIN(last_dirty_id)::BIGINT AS dirty_id
            FROM kcc20_projection_state
            WHERE name IN ('market', 'token_page', 'activity_feed', 'owner_orders', 'owner_portfolio_assets', 'owner_action_history')
            HAVING COUNT(*) = 6
        ), target AS (
            SELECT dirty.id
            FROM kcc20_projection_dirty dirty
            CROSS JOIN projection_cutoff cutoff
            WHERE dirty.id <= cutoff.dirty_id
            ORDER BY dirty.id
            LIMIT $1
        )
        DELETE FROM kcc20_projection_dirty dirty
        USING target
        WHERE dirty.id = target.id
        "#,
    )
    .bind(max_rows.max(1))
    .execute(pool)
    .await?;
    Ok(deleted.rows_affected())
}

pub const fn kcc20_market_projection_name() -> &'static str {
    KCC20_MARKET_PROJECTION
}

pub const fn kcc20_token_page_projection_name() -> &'static str {
    KCC20_TOKEN_PAGE_PROJECTION
}

pub const fn kcc20_activity_feed_projection_name() -> &'static str {
    KCC20_ACTIVITY_FEED_PROJECTION
}

pub const fn kcc20_owner_action_history_projection_name() -> &'static str {
    KCC20_OWNER_ACTION_HISTORY_PROJECTION
}

pub const fn kcc20_owner_orders_projection_name() -> &'static str {
    KCC20_OWNER_ORDERS_PROJECTION
}

pub const fn kcc20_owner_portfolio_assets_projection_name() -> &'static str {
    KCC20_OWNER_PORTFOLIO_ASSETS_PROJECTION
}

/// One spend action that still needs template or entrypoint backfill. Result
/// of the `reclassify` query.
#[derive(Debug, Clone)]
pub struct UnclassifiedCovenant {
    pub action_id: i64,
    pub covenant_id: Vec<u8>,
    pub spend_txid: Vec<u8>,
    pub spend_txid_hex: String,
    pub spent_outpoint_hash: Option<String>,
    pub spent_outpoint_index: Option<String>,
}

fn unclassified_covenant_from_row(r: PgRow) -> UnclassifiedCovenant {
    UnclassifiedCovenant {
        action_id: r.get("action_id"),
        covenant_id: r.get("covenant_id"),
        spend_txid: r.get("spend_txid"),
        spend_txid_hex: r.get("spend_txid_hex"),
        spent_outpoint_hash: r.get("spent_outpoint_hash"),
        spent_outpoint_index: r.get("spent_outpoint_index"),
    }
}

/// Find every spend action that still needs reclassification. A single reveal
/// script is enough to classify the covenant template, but each spend can use a
/// different entrypoint, so actions with missing entrypoints must be returned
/// independently. Wrapper and FeeTicket actions decoded before their argument
/// layouts were registered are also returned for repair. Limit is applied in SQL so
/// maintenance jobs can safely run bounded reclassification on large databases.
pub async fn unclassified_covenants_with_spends(
    pool: &PgPool,
    limit: u32,
) -> Result<Vec<UnclassifiedCovenant>> {
    let known_limit = limit as i64;
    let mut rows: Vec<UnclassifiedCovenant> = sqlx::query(
        r#"
        SELECT
            a.id                       AS action_id,
            c.covenant_id              AS covenant_id,
            a.txid                      AS spend_txid,
            encode(a.txid, 'hex')       AS spend_txid_hex,
            a.inputs #>> '{previousOutpoint,hash}'  AS spent_outpoint_hash,
            a.inputs #>> '{previousOutpoint,index}' AS spent_outpoint_index
        FROM covenant_actions a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        WHERE a.action = 'spend'
          AND c.template_name IN ('KCC20', 'KCC20Wrapper', 'KCC20Orderbook', 'KCC20FeeTicket')
          AND (
              a.entrypoint IS NULL
              OR (
                  c.template_name = 'KCC20'
                  AND a.entrypoint IN ('transfer', 'burn')
                  AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'nextStates'
              )
              OR (
                  c.template_name = 'KCC20Wrapper'
                  AND (
                      (a.entrypoint = 'wrap' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'tokenInputIndex')
                      OR (a.entrypoint = 'unwrap' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'wrappedInputIndex')
                  )
              )
              OR (
                  c.template_name = 'KCC20Orderbook'
                  AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep')
                  AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'ticketInputIndex'
              )
              OR (
                  c.template_name = 'KCC20FeeTicket'
                  AND (
                      (a.entrypoint = 'createFromUtilityBurn' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'ticketOwner')
                      OR (a.entrypoint = 'createBatchFromUtilityBurn' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ?& ARRAY['ticketOwner', 'quantity', 'firstTicketOutputIndex'])
                      OR (a.entrypoint = 'transferByOwnerSig' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ? 'recipientOwner')
                      OR (a.entrypoint = 'updateDenominationByOwnerSig' AND NOT COALESCE(a.decoded_args, '{}'::JSONB) ?& ARRAY['newDenomination', 'rootOutputIndex'])
                  )
              )
          )
        ORDER BY a.block_time_ms DESC, a.id DESC
        LIMIT NULLIF($1::BIGINT, 0)
        "#,
    )
    .bind(known_limit)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(unclassified_covenant_from_row)
    .collect();

    if limit > 0 && rows.len() >= limit as usize {
        return Ok(rows);
    }

    let generic_limit = if limit == 0 {
        0
    } else {
        i64::from(limit) - rows.len() as i64
    };
    rows.extend(
        sqlx::query(
            r#"
            SELECT
                a.id                       AS action_id,
                c.covenant_id              AS covenant_id,
                a.txid                      AS spend_txid,
                encode(a.txid, 'hex')       AS spend_txid_hex,
                a.inputs #>> '{previousOutpoint,hash}'  AS spent_outpoint_hash,
                a.inputs #>> '{previousOutpoint,index}' AS spent_outpoint_index
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE a.action = 'spend'
              AND (c.template_name IS NULL OR a.entrypoint IS NULL)
              AND (
                  c.template_name IS NULL
                  OR c.template_name NOT IN ('KCC20', 'KCC20Wrapper', 'KCC20Orderbook', 'KCC20FeeTicket')
              )
            ORDER BY a.block_time_ms DESC, a.id DESC
            LIMIT NULLIF($1::BIGINT, 0)
            "#,
        )
        .bind(generic_limit)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(unclassified_covenant_from_row),
    );

    Ok(rows)
}

/// `(covenant_id, address)` for every covenant that still has no template
/// classification and has not revealed a spend yet. Backs the
/// `auto-discover-spends` subcommand: callers walk each address's
/// full-transactions feed to ingest the spend the scanner missed (e.g.
/// covenants whose spend predated the spend-only-filter fix).
pub async fn unclassified_covenant_addresses(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(Vec<u8>, String)>> {
    let rows = sqlx::query(
        r#"SELECT covenant_id, address FROM covenants
           WHERE template_name IS NULL
             AND classification_status = 'unrevealed'
           ORDER BY created_at_ms DESC
           LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<Vec<u8>, _>("covenant_id"),
                r.get::<String, _>("address"),
            )
        })
        .collect())
}

/// Look up a single covenant's current `template_name`. Used by the
/// auto-discover loop to decide whether the just-ingested txs classified it.
pub async fn template_name_for(pool: &PgPool, covenant_id: &[u8]) -> Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT template_name FROM covenants WHERE covenant_id = $1")
            .bind(covenant_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(t,)| t))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadClaimRepairRow {
    pub covenant_id: Vec<u8>,
    pub covenant_id_hex: String,
    pub genesis_txid_hex: String,
    pub genesis_vout: i32,
}

pub async fn covenants_payload_claim_repair_candidates(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PayloadClaimRepairRow>> {
    let rows = sqlx::query(
        r#"
        SELECT c.covenant_id,
               encode(c.covenant_id, 'hex') AS covenant_id_hex,
               encode(c.genesis_txid, 'hex') AS genesis_txid_hex,
               c.genesis_vout
        FROM covenants c
        WHERE c.genesis_txid IS NOT NULL
          AND (
            c.claimed_template IS NULL
            OR (c.claimed_template IS NOT NULL AND c.covenant_id = c.script_hash)
          )
        ORDER BY c.created_at_ms DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PayloadClaimRepairRow {
            covenant_id: r.get("covenant_id"),
            covenant_id_hex: r.get("covenant_id_hex"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            genesis_vout: r.get("genesis_vout"),
        })
        .collect())
}

pub async fn covenants_missing_payload_claims(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PayloadClaimRepairRow>> {
    covenants_payload_claim_repair_candidates(pool, limit).await
}

#[derive(Debug, Clone)]
pub struct CovenantIdRepairCandidate {
    pub covenant_id: Vec<u8>,
    pub covenant_id_hex: String,
    pub genesis_txid_hex: String,
    pub genesis_vout: i32,
}

#[derive(Debug, Clone)]
pub struct CovenantOutpointIdentityRow {
    pub covenant_id: Vec<u8>,
    pub covenant_id_hex: String,
    pub canonical_covenant_id_known: bool,
    pub genesis_txid_hex: String,
    pub genesis_vout: i32,
}

/// Historical native covenant rows can be keyed by P2SH script_hash when REST
/// omitted output covenant bindings during ingest. Some continuation rows were
/// also mis-keyed as fresh canonical ids by recomputing a genesis id for a
/// non-genesis output. These are candidates for a backup-gated repair that
/// resolves the saved output back to its native covenant id.
pub async fn covenant_id_repair_candidates(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<CovenantIdRepairCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT covenant_id,
               encode(covenant_id, 'hex') AS covenant_id_hex,
               encode(genesis_txid, 'hex') AS genesis_txid_hex,
               genesis_vout
        FROM covenants
        WHERE covenant_id = script_hash
           OR EXISTS (
               SELECT 1
               FROM covenant_actions deploy
               JOIN covenant_actions spend
                 ON spend.txid = deploy.txid
                AND spend.action = 'spend'
               WHERE deploy.covenant_id = covenants.covenant_id
                 AND deploy.action = 'deploy'
           )
        ORDER BY created_at_ms ASC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| CovenantIdRepairCandidate {
            covenant_id: r.get("covenant_id"),
            covenant_id_hex: r.get("covenant_id_hex"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            genesis_vout: r.get("genesis_vout"),
        })
        .collect())
}

pub async fn covenant_identity_for_outpoint(
    pool: &PgPool,
    txid_hex: &str,
    vout: i32,
) -> Result<Option<CovenantOutpointIdentityRow>> {
    let row = sqlx::query(
        r#"
        SELECT c.covenant_id,
               encode(c.covenant_id, 'hex') AS covenant_id_hex,
               (c.covenant_id <> c.script_hash) AS canonical_covenant_id_known,
               encode(c.genesis_txid, 'hex') AS genesis_txid_hex,
               c.genesis_vout
        FROM covenant_utxos u
        JOIN covenants c ON c.covenant_id = u.covenant_id
        WHERE u.txid = decode($1, 'hex') AND u.vout = $2
        LIMIT 1
        "#,
    )
    .bind(txid_hex)
    .bind(vout)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| CovenantOutpointIdentityRow {
        covenant_id: r.get("covenant_id"),
        covenant_id_hex: r.get("covenant_id_hex"),
        canonical_covenant_id_known: r.get("canonical_covenant_id_known"),
        genesis_txid_hex: r.get("genesis_txid_hex"),
        genesis_vout: r.get("genesis_vout"),
    }))
}

/// Move a legacy script-hash keyed covenant row to its canonical KIP-20
/// covenant id, preserving child rows. Returns true when any row moved.
pub async fn rekey_covenant_id(
    pool: &PgPool,
    old_covenant_id: &[u8],
    new_covenant_id: &[u8],
) -> Result<bool> {
    if old_covenant_id == new_covenant_id {
        return Ok(false);
    }

    let mut tx = crate::PgPersister::begin_repair_transaction(pool).await?;
    let moved = rekey_covenant_id_in_tx(&mut tx, old_covenant_id, new_covenant_id).await?;
    tx.commit().await?;
    Ok(moved)
}

pub(crate) async fn rekey_covenant_id_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    old_covenant_id: &[u8],
    new_covenant_id: &[u8],
) -> Result<bool> {
    if old_covenant_id == new_covenant_id {
        return Ok(false);
    }

    let old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM covenants WHERE covenant_id = $1)")
            .bind(old_covenant_id)
            .fetch_one(&mut **tx)
            .await?;
    if !old_exists {
        return Ok(false);
    }

    sqlx::query(
        r#"
        INSERT INTO covenants
            (covenant_id, address, script_version, script_hash, template_name,
             genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
             claimed_template, claimed_args, claim_source, claim_verified,
             claim_verified_at_ms, classification_kind, classification_status)
        SELECT $2, address, script_version, script_hash, template_name,
               genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
               claimed_template, claimed_args, claim_source, claim_verified,
               claim_verified_at_ms, classification_kind, classification_status
        FROM covenants
        WHERE covenant_id = $1
        ON CONFLICT (covenant_id) DO UPDATE
          SET template_name = COALESCE(covenants.template_name, EXCLUDED.template_name),
              constructor_args = COALESCE(covenants.constructor_args, EXCLUDED.constructor_args),
              claimed_template = COALESCE(covenants.claimed_template, EXCLUDED.claimed_template),
              claimed_args = COALESCE(covenants.claimed_args, EXCLUDED.claimed_args),
              claim_source = COALESCE(covenants.claim_source, EXCLUDED.claim_source),
              claim_verified = covenants.claim_verified OR EXCLUDED.claim_verified,
              claim_verified_at_ms = COALESCE(covenants.claim_verified_at_ms, EXCLUDED.claim_verified_at_ms),
              classification_kind = CASE
                  WHEN covenants.classification_status = 'matched' THEN covenants.classification_kind
                  ELSE EXCLUDED.classification_kind
              END,
              classification_status = CASE
                  WHEN covenants.classification_status = 'matched' THEN covenants.classification_status
                  ELSE EXCLUDED.classification_status
              END
        "#,
    )
    .bind(old_covenant_id)
    .bind(new_covenant_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        DELETE FROM covenant_actions old
        USING covenant_actions existing
        WHERE old.covenant_id = $1
          AND existing.covenant_id = $2
          AND old.txid = existing.txid
          AND old.action = existing.action
          AND (
              old.action = 'deploy'
              OR (
                  old.action = 'spend'
                  AND COALESCE(old.inputs #>> '{previousOutpoint,hash}', '') = COALESCE(existing.inputs #>> '{previousOutpoint,hash}', '')
                  AND COALESCE(old.inputs #>> '{previousOutpoint,index}', '') = COALESCE(existing.inputs #>> '{previousOutpoint,index}', '')
              )
              OR COALESCE(old.outputs->>'vout', '') = COALESCE(existing.outputs->>'vout', '')
          )
        "#,
    )
    .bind(old_covenant_id)
    .bind(new_covenant_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        DELETE FROM kcc20_holders old
        USING kcc20_holders existing
        WHERE old.covenant_id = $1
          AND existing.covenant_id = $2
          AND old.owner_identifier = existing.owner_identifier
          AND old.identifier_type = existing.identifier_type
        "#,
    )
    .bind(old_covenant_id)
    .bind(new_covenant_id)
    .execute(&mut **tx)
    .await?;

    let utxos = sqlx::query("UPDATE covenant_utxos SET covenant_id = $2 WHERE covenant_id = $1")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    let actions =
        sqlx::query("UPDATE covenant_actions SET covenant_id = $2 WHERE covenant_id = $1")
            .bind(old_covenant_id)
            .bind(new_covenant_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();
    let holders = sqlx::query("UPDATE kcc20_holders SET covenant_id = $2 WHERE covenant_id = $1")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();

    let action_canonical_refs = sqlx::query(
        "UPDATE covenant_actions SET canonical_token_id = $2 WHERE canonical_token_id = $1",
    )
    .bind(old_covenant_id)
    .bind(new_covenant_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let activity_rows =
        sqlx::query("UPDATE kcc20_activity_feed SET token_id = $2 WHERE token_id = $1")
            .bind(old_covenant_id)
            .bind(new_covenant_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    sqlx::query("DELETE FROM kcc20_market_summaries WHERE token_id = $1 AND EXISTS (SELECT 1 FROM kcc20_market_summaries WHERE token_id = $2)")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?;
    let market_summaries =
        sqlx::query("UPDATE kcc20_market_summaries SET token_id = $2 WHERE token_id = $1")
            .bind(old_covenant_id)
            .bind(new_covenant_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    sqlx::query("UPDATE kcc20_token_summaries SET wrapper_id = $2 WHERE wrapper_id = $1")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM kcc20_token_summaries WHERE token_id = $1 AND EXISTS (SELECT 1 FROM kcc20_token_summaries WHERE token_id = $2)")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?;
    let token_summaries =
        sqlx::query("UPDATE kcc20_token_summaries SET token_id = $2 WHERE token_id = $1")
            .bind(old_covenant_id)
            .bind(new_covenant_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    sqlx::query(
        "UPDATE kcc20_wrapper_summaries SET canonical_token_id = $2 WHERE canonical_token_id = $1",
    )
    .bind(old_covenant_id)
    .bind(new_covenant_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM kcc20_wrapper_summaries WHERE wrapper_id = $1 AND EXISTS (SELECT 1 FROM kcc20_wrapper_summaries WHERE wrapper_id = $2)")
        .bind(old_covenant_id)
        .bind(new_covenant_id)
        .execute(&mut **tx)
        .await?;
    let wrapper_summaries =
        sqlx::query("UPDATE kcc20_wrapper_summaries SET wrapper_id = $2 WHERE wrapper_id = $1")
            .bind(old_covenant_id)
            .bind(new_covenant_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    let payment_channels =
        rekey_api_payment_channel_rows(tx, old_covenant_id, new_covenant_id).await?;

    sqlx::query("DELETE FROM covenants WHERE covenant_id = $1")
        .bind(old_covenant_id)
        .execute(&mut **tx)
        .await?;

    Ok(utxos > 0
        || actions > 0
        || holders > 0
        || action_canonical_refs > 0
        || activity_rows > 0
        || market_summaries > 0
        || token_summaries > 0
        || wrapper_summaries > 0
        || payment_channels > 0)
}

async fn rekey_api_payment_channel_rows(
    tx: &mut Transaction<'_, Postgres>,
    old_covenant_id: &[u8],
    new_covenant_id: &[u8],
) -> Result<u64> {
    let old_channel_id = hex::encode(old_covenant_id);
    let new_channel_id = hex::encode(new_covenant_id);

    let old_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM api_payment_channels WHERE channel_id = $1)",
    )
    .bind(&old_channel_id)
    .fetch_one(&mut **tx)
    .await?;
    if !old_exists {
        return Ok(0);
    }

    sqlx::query(
        r#"
        INSERT INTO api_payment_channels (
            channel_id, network_id, payer_identifier, payer_pubkey,
            provider_pubkey, provider_identifier, scope, deposit_sompi,
            reserve_sompi, spent_sompi, latest_sequence, status, open_txid,
            settlement_txid, refund_txid, refund_after_daa, pricing_policy_id,
            indexed_at_ms, created_at_ms, updated_at_ms
        )
        SELECT $2, network_id, payer_identifier, payer_pubkey,
               provider_pubkey, provider_identifier, scope, deposit_sompi,
               reserve_sompi, spent_sompi, latest_sequence, status, open_txid,
               settlement_txid, refund_txid, refund_after_daa, pricing_policy_id,
               indexed_at_ms, created_at_ms, updated_at_ms
        FROM api_payment_channels
        WHERE channel_id = $1
        ON CONFLICT (channel_id) DO UPDATE SET
            reserve_sompi = GREATEST(api_payment_channels.reserve_sompi, EXCLUDED.reserve_sompi),
            spent_sompi = GREATEST(api_payment_channels.spent_sompi, EXCLUDED.spent_sompi),
            latest_sequence = GREATEST(api_payment_channels.latest_sequence, EXCLUDED.latest_sequence),
            updated_at_ms = GREATEST(api_payment_channels.updated_at_ms, EXCLUDED.updated_at_ms)
        "#,
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        DELETE FROM api_payment_vouchers old
        USING api_payment_vouchers existing
        WHERE old.channel_id = $1
          AND existing.channel_id = $2
          AND (
              old.sequence = existing.sequence
              OR old.credential_hash = existing.credential_hash
          )
        "#,
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?;
    let vouchers =
        sqlx::query("UPDATE api_payment_vouchers SET channel_id = $2 WHERE channel_id = $1")
            .bind(&old_channel_id)
            .bind(&new_channel_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    let usage =
        sqlx::query("UPDATE api_payment_usage_events SET channel_id = $2 WHERE channel_id = $1")
            .bind(&old_channel_id)
            .bind(&new_channel_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    let settlements =
        sqlx::query("UPDATE api_payment_settlements SET channel_id = $2 WHERE channel_id = $1")
            .bind(&old_channel_id)
            .bind(&new_channel_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();

    sqlx::query(
        r#"
        DELETE FROM api_payment_settlement_authorizations old
        USING api_payment_settlement_authorizations existing
        WHERE old.channel_id = $1
          AND existing.channel_id = $2
          AND (
              old.sequence = existing.sequence
              OR old.settlement_txid = existing.settlement_txid
              OR old.metadata_hash = existing.metadata_hash
          )
        "#,
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?;
    let settlement_auths = sqlx::query(
        "UPDATE api_payment_settlement_authorizations SET channel_id = $2 WHERE channel_id = $1",
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    sqlx::query(
        r#"
        DELETE FROM api_payment_channel_close_requests old
        USING api_payment_channel_close_requests existing
        WHERE old.channel_id = $1
          AND existing.channel_id = $2
          AND old.credential_hash = existing.credential_hash
        "#,
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?;
    let close_requests = sqlx::query(
        "UPDATE api_payment_channel_close_requests SET channel_id = $2 WHERE channel_id = $1",
    )
    .bind(&old_channel_id)
    .bind(&new_channel_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let channels = sqlx::query("DELETE FROM api_payment_channels WHERE channel_id = $1")
        .bind(&old_channel_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();

    Ok(vouchers + usage + settlements + settlement_auths + close_requests + channels)
}

/// Older scans could store a continuation output as a deploy before the row was
/// rekeyed to the parent covenant id. Once a continuation action exists for the
/// same covenant/tx, the deploy row is stale duplicate history.
pub async fn delete_misclassified_continuation_deploy_actions(pool: &PgPool) -> Result<u64> {
    let mut tx = crate::PgPersister::begin_repair_transaction(pool).await?;
    let result = sqlx::query(
        r#"
        DELETE FROM covenant_actions deploy
        USING covenant_actions continuation
        WHERE deploy.covenant_id = continuation.covenant_id
          AND deploy.txid = continuation.txid
          AND deploy.action = 'deploy'
          AND continuation.action = 'continuation'
        "#,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

pub async fn store_payload_claim_for_covenant(
    pool: &PgPool,
    covenant_id: &[u8],
    claim: &ClaimedDeployment,
) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let rows_affected = store_payload_claim_for_covenant_tx(&mut tx, covenant_id, claim).await?;
    tx.commit().await?;

    Ok(rows_affected)
}

pub async fn store_payload_claim_for_covenant_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    covenant_id: &[u8],
    claim: &ClaimedDeployment,
) -> Result<u64> {
    let blob = claim::claimed_args_jsonb(claim);
    let result = sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = $1,
               claimed_args = $2,
               claim_source = COALESCE(claim_source, 'payload')
           WHERE covenant_id = $3
             AND claimed_template IS NULL"#,
    )
    .bind(&claim.tmpl)
    .bind(&blob)
    .bind(covenant_id)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}

#[derive(Debug, Clone)]
pub struct Kcc20RepairStateSpec {
    pub script_hash: Vec<u8>,
    pub owner_identifier: Vec<u8>,
    pub identifier_type: i16,
    pub amount: String,
    pub is_minter: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20HolderRepairResult {
    pub dry_run: bool,
    pub canonicalized_utxos: u64,
    pub state_updates: u64,
    pub source_holders_deleted: u64,
    pub holders_deleted: u64,
    pub holders_inserted: u64,
}

pub async fn refresh_action_canonical_token_ids_for_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    txid: &[u8],
) -> Result<u64> {
    Ok(sqlx::query(
        r#"
        WITH candidates AS (
            SELECT
                a.id,
                lower(COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(a.outputs->'state'->>'canonicalTokenId', ''),
                    NULLIF(a.decoded_args->>'utilityTokenId', ''),
                    NULLIF(a.outputs->'state'->>'utilityTokenId', '')
                )) AS token_id_hex
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE a.txid = $1
              AND COALESCE(c.template_name, c.claimed_template) IN (
                'KCC20', 'KCC20Orderbook',
                'KCC20Wrapper', 'KCC20FeeTicket'
              )
        )
        UPDATE covenant_actions a
        SET canonical_token_id = decode(candidates.token_id_hex, 'hex')
        FROM candidates
        WHERE a.id = candidates.id
          AND candidates.token_id_hex ~ '^[0-9a-f]{64}$'
          AND a.canonical_token_id IS DISTINCT FROM decode(candidates.token_id_hex, 'hex')
        "#,
    )
    .bind(txid)
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

fn normalized_filter_values(value: Option<&str>, aliases: &[String]) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        values.insert(value.to_ascii_lowercase());
    }
    for alias in aliases {
        let alias = alias.trim();
        if !alias.is_empty() {
            values.insert(alias.to_ascii_lowercase());
        }
    }
    values.into_iter().collect()
}

/// Repair historical KCC20 holder state without hand-written SQL.
///
/// `script_hashes` maps active P2SH outputs to the canonical KIP-20 token id.
/// `state_specs` then supplies KCC20 state for active outputs whose state was
/// missed by older scanner/decoder builds. Holder aggregates are rebuilt from
/// active UTXO state at the end of the same transaction.
pub async fn repair_kcc20_holders(
    pool: &PgPool,
    token_id: &[u8],
    script_hashes: &[Vec<u8>],
    state_specs: &[Kcc20RepairStateSpec],
    last_change_ms: i64,
    overwrite_states: bool,
    dry_run: bool,
) -> Result<Kcc20HolderRepairResult> {
    anyhow::ensure!(token_id.len() == 32, "token-id must be 32 bytes");
    for script_hash in script_hashes {
        anyhow::ensure!(script_hash.len() == 32, "script-hash must be 32 bytes");
    }
    for spec in state_specs {
        anyhow::ensure!(
            spec.script_hash.len() == 32,
            "state script-hash must be 32 bytes"
        );
        anyhow::ensure!(
            spec.owner_identifier.len() == 32,
            "state owner identifier must be 32 bytes"
        );
        anyhow::ensure!(
            (0..=4).contains(&spec.identifier_type),
            "state owner scheme must be 0 through 4"
        );
        anyhow::ensure!(
            spec.amount.chars().all(|c| c.is_ascii_digit()) && !spec.amount.is_empty(),
            "state amount must be a decimal integer string"
        );
    }

    let mut tx = pool.begin().await?;
    let mut canonicalized_utxos = 0;
    let mut source_covenant_ids = BTreeSet::new();
    for script_hash in script_hashes {
        for covenant_id in sqlx::query_scalar::<_, Vec<u8>>(
            r#"
            SELECT DISTINCT covenant_id
            FROM covenant_utxos
            WHERE status = 'active'
              AND covenant_id <> $1
              AND length(script_pubkey) = 35
              AND get_byte(script_pubkey, 0) = 170
              AND get_byte(script_pubkey, 1) = 32
              AND get_byte(script_pubkey, 34) = 135
              AND substring(script_pubkey FROM 3 FOR 32) = $2
            "#,
        )
        .bind(token_id)
        .bind(script_hash)
        .fetch_all(&mut *tx)
        .await?
        {
            source_covenant_ids.insert(covenant_id);
        }

        canonicalized_utxos += sqlx::query(
            r#"
            UPDATE covenant_utxos
            SET covenant_id = $1
            WHERE status = 'active'
              AND covenant_id <> $1
              AND length(script_pubkey) = 35
              AND get_byte(script_pubkey, 0) = 170
              AND get_byte(script_pubkey, 1) = 32
              AND get_byte(script_pubkey, 34) = 135
              AND substring(script_pubkey FROM 3 FOR 32) = $2
            "#,
        )
        .bind(token_id)
        .bind(script_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }

    let mut source_holders_deleted = 0;
    for covenant_id in source_covenant_ids {
        source_holders_deleted += sqlx::query("DELETE FROM kcc20_holders WHERE covenant_id = $1")
            .bind(covenant_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    }

    let mut state_updates = 0;
    for spec in state_specs {
        let state = json!({
            "owner": hex::encode(&spec.owner_identifier),
            "ownerScheme": spec.identifier_type,
            "ownerSchemeName": kcc20_identifier_type_name(spec.identifier_type),
            "amount": spec.amount,
            "isMintAuthority": spec.is_minter,
        });
        state_updates += sqlx::query(
            r#"
            UPDATE covenant_utxos
            SET state = $3
            WHERE covenant_id = $1
              AND status = 'active'
              AND ($4 OR state IS NULL)
              AND length(script_pubkey) = 35
              AND get_byte(script_pubkey, 0) = 170
              AND get_byte(script_pubkey, 1) = 32
              AND get_byte(script_pubkey, 34) = 135
              AND substring(script_pubkey FROM 3 FOR 32) = $2
            "#,
        )
        .bind(token_id)
        .bind(&spec.script_hash)
        .bind(state)
        .bind(overwrite_states)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }

    let holders_deleted = sqlx::query("DELETE FROM kcc20_holders WHERE covenant_id = $1")
        .bind(token_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    let holders_inserted = sqlx::query(
        r#"
        INSERT INTO kcc20_holders
            (covenant_id, owner_identifier, identifier_type, amount_total,
             utxo_count, is_minter, last_change_ms)
        SELECT
            covenant_id,
            decode(state->>'owner', 'hex')                AS owner_identifier,
            (state->>'ownerScheme')::SMALLINT             AS identifier_type,
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
    .bind(token_id)
    .bind(last_change_ms)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }

    Ok(Kcc20HolderRepairResult {
        dry_run,
        canonicalized_utxos,
        state_updates,
        source_holders_deleted,
        holders_deleted,
        holders_inserted,
    })
}

/// Row counts for the API's /health surface.
///
/// Keep this path cheap: /tx/{txid}/settlement-status includes scanner health,
/// so health must never depend on an exact global active-UTXO scan.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexerCounts {
    pub covenants: i64,
    pub active_utxos: i64,
    pub actions: i64,
}

async fn counts_in_tx(tx: &mut Transaction<'_, Postgres>) -> Result<IndexerCounts> {
    let covenants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM covenants")
        .fetch_one(&mut **tx)
        .await?;
    let active_utxos: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM covenant_utxos WHERE status='active'")
            .fetch_one(&mut **tx)
            .await?;
    let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM covenant_actions")
        .fetch_one(&mut **tx)
        .await?;

    Ok(IndexerCounts {
        covenants,
        active_utxos,
        actions,
    })
}

async fn health_counts_in_tx(tx: &mut Transaction<'_, Postgres>) -> Result<IndexerCounts> {
    let covenants: i64 = sqlx::query_scalar(
        r#"SELECT COALESCE(SUM(covenant_count), 0)::BIGINT
           FROM covenant_template_summaries"#,
    )
    .fetch_one(&mut **tx)
    .await?;
    let active_utxos: i64 = sqlx::query_scalar(
        r#"SELECT COALESCE(SUM(active_utxos), 0)::BIGINT
           FROM covenant_template_summaries"#,
    )
    .fetch_one(&mut **tx)
    .await?;
    let actions: i64 = sqlx::query_scalar(
        r#"SELECT COALESCE(SUM(action_count), 0)::BIGINT
           FROM covenant_template_summaries"#,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(IndexerCounts {
        covenants,
        active_utxos,
        actions,
    })
}

pub async fn latest_activity_feed_time_ms(pool: &PgPool) -> Result<Option<i64>> {
    let latest = if table_exists(pool, "kcc20_activity_feed").await? {
        sqlx::query_scalar(
            "SELECT block_time_ms FROM kcc20_activity_feed ORDER BY block_time_ms DESC, txid DESC, id DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await?
    } else {
        None
    };

    Ok(latest)
}

pub async fn counts(pool: &PgPool) -> Result<IndexerCounts> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, HEALTH_STATEMENT_TIMEOUT).await?;
    let counts = counts_in_tx(&mut tx).await?;
    tx.commit().await?;
    Ok(counts)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationBucket {
    pub classification_kind: String,
    pub classification_status: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnknownCounts {
    pub total: i64,
    pub unrevealed: i64,
    pub unmatched: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerHealth {
    pub cursor_key: Option<String>,
    pub cursor_blue_score: Option<i64>,
    pub rest_database_blue_score: Option<i64>,
    pub cursor_updated_at_ms: Option<i64>,
    pub cursor_age_ms: Option<i64>,
    pub rest_observation_age_ms: Option<i64>,
    pub rest_observation_fresh: bool,
    pub live_acceptance_observed_at_ms: Option<i64>,
    pub live_acceptance_blue_score: Option<i64>,
    pub live_acceptance_age_ms: Option<i64>,
    pub live_acceptance_fresh: bool,
    pub latest_block_blue_score: Option<i64>,
    pub latest_block_time_ms: Option<i64>,
    pub latest_block_indexed_at_ms: Option<i64>,
    pub latest_action_time_ms: Option<i64>,
    pub db_cursor_lag_blocks: Option<i64>,
    pub rest_db_lag_blocks: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexerHealthSnapshot {
    pub counts: IndexerCounts,
    pub scanner: ScannerHealth,
    pub classifications: Vec<ClassificationBucket>,
    pub unknown: UnknownCounts,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerSummary {
    pub ok: bool,
    pub source: String,
    pub counts: IndexerCounts,
    pub scanner: ScannerHealth,
    pub classifications: Vec<ClassificationBucket>,
    pub unknown: UnknownCounts,
    pub templates: Vec<CovenantTemplateSummaryRow>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerSearchResult {
    pub kind: String,
    pub label: String,
    pub description: Option<String>,
    pub id: Option<String>,
    pub path: String,
    pub status: Option<String>,
    pub score: i32,
}

pub async fn health_snapshot(pool: &PgPool) -> Result<IndexerHealthSnapshot> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, HEALTH_STATEMENT_TIMEOUT).await?;
    let counts = health_counts_in_tx(&mut tx).await?;

    let classification_rows = sqlx::query(
        r#"SELECT classification_kind, classification_status, COUNT(*) AS count
           FROM covenants
           GROUP BY classification_kind, classification_status
           ORDER BY classification_kind, classification_status"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let classifications: Vec<ClassificationBucket> = classification_rows
        .into_iter()
        .map(|r| ClassificationBucket {
            classification_kind: r.get("classification_kind"),
            classification_status: r.get("classification_status"),
            count: r.get("count"),
        })
        .collect();

    let unknown = classifications.iter().fold(
        UnknownCounts {
            total: 0,
            unrevealed: 0,
            unmatched: 0,
        },
        |mut acc, bucket| {
            if bucket.classification_kind == "unknown" {
                acc.total += bucket.count;
                match bucket.classification_status.as_str() {
                    "unrevealed" => acc.unrevealed += bucket.count,
                    "unmatched" => acc.unmatched += bucket.count,
                    _ => {}
                }
            }
            acc
        },
    );

    let scanner = scanner_health_in_tx(&mut tx).await?;

    let snapshot = IndexerHealthSnapshot {
        counts,
        scanner,
        classifications,
        unknown,
    };
    tx.commit().await?;
    Ok(snapshot)
}

pub async fn explorer_summary(pool: &PgPool) -> Result<ExplorerSummary> {
    let snapshot = health_snapshot(pool).await?;
    let templates = covenant_template_summaries(pool).await?;
    Ok(ExplorerSummary {
        ok: true,
        source: "postgres".to_string(),
        counts: snapshot.counts,
        scanner: snapshot.scanner,
        classifications: snapshot.classifications,
        unknown: snapshot.unknown,
        templates,
    })
}

async fn scanner_health_in_tx(tx: &mut Transaction<'_, Postgres>) -> Result<ScannerHealth> {
    let cursor_row = sqlx::query(
        r#"SELECT key, value, updated_at_ms,
                  GREATEST(
                      EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - updated_at_ms,
                      0
                  ) AS cursor_age_ms
           FROM indexer_state
           WHERE key IN (
               'chain_live_near_tip_repair_cursor',
               'chain_live_repair_cursor',
               'chain_realtime_tip_cursor',
               'chain_live_scan_cursor',
               'chain_scan_cursor'
           )
           ORDER BY CASE key
               WHEN 'chain_live_near_tip_repair_cursor' THEN 0
               WHEN 'chain_live_repair_cursor' THEN 1
               WHEN 'chain_realtime_tip_cursor' THEN 2
               WHEN 'chain_live_scan_cursor' THEN 3
               ELSE 4
           END
           LIMIT 1"#,
    )
    .fetch_optional(&mut **tx)
    .await?;
    let (
        cursor_key,
        cursor_blue_score,
        rest_database_blue_score,
        rest_database_observed_at_ms,
        cursor_updated_at_ms,
        cursor_age_ms,
    ) = cursor_row
        .map(|r| {
            let value: Value = r.get("value");
            (
                Some(r.get::<String, _>("key")),
                value.get("blue_score").and_then(Value::as_i64),
                value
                    .get("rest_database_blue_score")
                    .and_then(Value::as_i64),
                value
                    .get("rest_database_observed_at_ms")
                    .and_then(Value::as_i64)
                    .or_else(|| Some(r.get::<i64, _>("updated_at_ms"))),
                Some(r.get::<i64, _>("updated_at_ms")),
                Some(r.get::<i64, _>("cursor_age_ms")),
            )
        })
        .unwrap_or((None, None, None, None, None, None));

    let latest_block_row = sqlx::query(
        r#"SELECT blue_score, timestamp_ms, indexed_at_ms
           FROM blocks
           WHERE is_chain_block
           ORDER BY blue_score DESC
           LIMIT 1"#,
    )
    .fetch_optional(&mut **tx)
    .await?;
    let (latest_block_blue_score, latest_block_time_ms, latest_block_indexed_at_ms) =
        latest_block_row
            .map(|r| {
                (
                    Some(r.get::<i64, _>("blue_score")),
                    Some(r.get::<i64, _>("timestamp_ms")),
                    Some(r.get::<i64, _>("indexed_at_ms")),
                )
            })
            .unwrap_or((None, None, None));

    let latest_action_time_ms: Option<i64> = sqlx::query_scalar(
        r#"SELECT block_time_ms
           FROM covenant_actions
           ORDER BY block_time_ms DESC
           LIMIT 1"#,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let heartbeat_row = sqlx::query(
        "SELECT value, updated_at_ms FROM indexer_state WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .fetch_optional(&mut **tx)
    .await?;
    let (live_acceptance_blue_score, live_acceptance_observed_at_ms) = heartbeat_row
        .map(|row| {
            let value: Value = row.get("value");
            (
                value.get("blue_score").and_then(Value::as_i64),
                Some(row.get::<i64, _>("updated_at_ms")),
            )
        })
        .unwrap_or((None, None));
    let live_acceptance_age_ms = live_acceptance_observed_at_ms
        .map(|observed_at_ms| now_ms.saturating_sub(observed_at_ms).max(0));
    let live_acceptance_fresh =
        live_acceptance_age_ms.is_some_and(|age_ms| age_ms <= LIVE_ACCEPTANCE_FRESH_MS);
    let rest_observation_age_ms = rest_database_blue_score
        .and(rest_database_observed_at_ms)
        .map(|observed_at_ms| now_ms.saturating_sub(observed_at_ms).max(0));
    let rest_observation_fresh =
        rest_observation_age_ms.is_some_and(|age_ms| age_ms <= REST_OBSERVATION_FRESH_MS);
    let db_cursor_lag_blocks = match (rest_database_blue_score, cursor_blue_score) {
        _ if !rest_observation_fresh => None,
        (Some(latest), Some(cursor)) => Some((latest - cursor).max(0)),
        _ => None,
    };
    let rest_db_lag_blocks = rest_db_lag_blocks(
        latest_block_blue_score.max(live_acceptance_blue_score),
        rest_database_blue_score,
    );

    Ok(ScannerHealth {
        cursor_key,
        cursor_blue_score,
        rest_database_blue_score,
        cursor_updated_at_ms,
        cursor_age_ms,
        rest_observation_age_ms,
        rest_observation_fresh,
        live_acceptance_observed_at_ms,
        live_acceptance_blue_score,
        live_acceptance_age_ms,
        live_acceptance_fresh,
        latest_block_blue_score,
        latest_block_time_ms,
        latest_block_indexed_at_ms,
        latest_action_time_ms,
        db_cursor_lag_blocks,
        rest_db_lag_blocks,
    })
}

pub async fn scanner_health(pool: &PgPool) -> Result<ScannerHealth> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, HEALTH_STATEMENT_TIMEOUT).await?;
    let scanner = scanner_health_in_tx(&mut tx).await?;
    tx.commit().await?;
    Ok(scanner)
}

/// One covenant row, shaped to match `CovenantSummary` from the in-memory
/// engine so the API's `/covenants` JSON stays the same. `claimed_*` fields
/// surface the wallet-declared envelope; `claim_verified` flips when the
/// first spend cross-validates them against the on-chain reveal.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantSummaryRow {
    pub covenant_id_hex: String,
    pub script_hash_hex: String,
    pub canonical_covenant_id_known: bool,
    pub identity_source: String,
    pub address: String,
    pub template: Option<String>,
    pub constructor: Option<Value>,
    pub active_utxos: i64,
    pub total_amount_sompi: i64,
    pub genesis_txid_hex: String,
    pub created_at_ms: i64,
    pub claimed_template: Option<String>,
    pub claimed_args: Option<Value>,
    pub claim_source: Option<String>,
    pub claim_verified: bool,
    pub claim_verified_at_ms: Option<i64>,
    pub classification_kind: String,
    pub classification_status: String,
    pub inscription_protocol: Option<String>,
}

/// One row of `covenant_actions`, shaped to mirror `CovenantEvent` JSON from
/// the in-memory engine — `kind` aligns with `EventKind` variants.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantActionRow {
    pub covenant_id_hex: String,
    pub canonical_token_id_hex: Option<String>,
    pub script_hash_hex: String,
    pub address: String,
    pub txid_hex: String,
    pub block_hash_hex: String,
    pub block_time_ms: i64,
    pub action: String,
    pub entrypoint: Option<String>,
    pub inputs: Option<Value>,
    pub outputs: Option<Value>,
    pub decoded_args: Option<Value>,
    pub classification_kind: String,
    pub classification_status: String,
    pub inscription_protocol: Option<String>,
}

/// One verified snapshot-controller claim plus the KCC20 reserve input from
/// the same transaction. This avoids one transaction lookup per replayed claim.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotClaimActionRow {
    pub controller_id_hex: String,
    pub txid_hex: String,
    pub block_hash_hex: String,
    pub block_time_ms: i64,
    pub inputs: Option<Value>,
    pub decoded_args: Option<Value>,
    pub classification_kind: String,
    pub classification_status: String,
    pub controller_template_name: Option<String>,
    pub token_action_count: i64,
    pub token_inputs: Option<Value>,
    pub token_template_name: Option<String>,
    pub token_classification_kind: Option<String>,
    pub token_classification_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotClaimActionPage {
    pub epoch: String,
    pub revision: i64,
    pub total: i64,
    pub content_commitment: String,
    pub items: Vec<SnapshotClaimActionRow>,
}

/// One row of `covenant_utxos` — used both for active-UTXO listings and for
/// the per-covenant detail page.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantUtxoRow {
    pub covenant_id_hex: String,
    pub script_hash_hex: String,
    pub address: String,
    pub txid_hex: String,
    pub vout: i32,
    pub amount_sompi: i64,
    pub amount_sompi_exact: String,
    pub state: Option<Value>,
    pub status: String,
    pub spent_by_txid_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20FeeReceiptsPage {
    pub receipts: Vec<CovenantUtxoRow>,
    pub total_count: i64,
    pub protocol_claimable_sompi: String,
    pub creator_claimable_sompi: String,
}

/// Active, authenticated receipt states for one fee-market lineage. This is
/// current claimable state, not a historical accrual or coverage certificate.
pub async fn kcc20_fee_receipts_page(
    pool: &PgPool,
    market_id_hex: &str,
    limit: i64,
    offset: i64,
) -> Result<Kcc20FeeReceiptsPage> {
    let market_id = hex::decode(market_id_hex)?;
    anyhow::ensure!(market_id.len() == 32, "market ID must be 32 bytes");
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx).await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, COVENANT_LIST_STATEMENT_TIMEOUT).await?;
    let summary = sqlx::query(
        r#"SELECT COUNT(*) AS total_count,
                  COALESCE(SUM((u.state->>'protocol_amount')::NUMERIC), 0)::TEXT AS protocol_total,
                  COALESCE(SUM((u.state->>'creator_amount')::NUMERIC), 0)::TEXT AS creator_total,
                  COALESCE(BOOL_AND(u.amount_sompi =
                      (u.state->>'protocol_amount')::BIGINT +
                      (u.state->>'creator_amount')::BIGINT), TRUE) AS values_match
           FROM covenant_utxos u
           WHERE u.covenant_id = $1 AND u.status = 'active'
             AND u.state->>'roleName' = 'receipt'
             AND u.state->>'market' = $2"#,
    )
    .bind(&market_id)
    .bind(market_id_hex)
    .fetch_one(&mut *tx).await?;
    anyhow::ensure!(summary.get::<bool, _>("values_match"), "active fee receipt value mismatch");
    let rows = sqlx::query(
        r#"SELECT encode(u.covenant_id,'hex') AS covenant_id_hex,
                  encode(substring(u.script_pubkey FROM 3 FOR 32),'hex') AS script_hash_hex,
                  u.address, encode(u.txid,'hex') AS txid_hex, u.vout,
                  u.amount_sompi, u.state, u.status,
                  encode(u.spent_by_txid,'hex') AS spent_by_txid_hex
           FROM covenant_utxos u
           WHERE u.covenant_id = $1 AND u.status = 'active'
             AND u.state->>'roleName' = 'receipt'
             AND u.state->>'market' = $2
           ORDER BY u.txid ASC, u.vout ASC LIMIT $3 OFFSET $4"#,
    )
    .bind(&market_id)
    .bind(market_id_hex)
    .bind(limit.clamp(1, 100))
    .bind(offset.max(0))
    .fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let receipts = rows.into_iter().map(|r| {
        let state: Value = r.get("state");
        let value: i64 = r.get("amount_sompi");
        let protocol = state["protocol_amount"].as_str().context("receipt protocol amount")?.parse::<i64>()?;
        let creator = state["creator_amount"].as_str().context("receipt creator amount")?.parse::<i64>()?;
        anyhow::ensure!(value > 0 && protocol >= 0 && creator >= 0
            && protocol.checked_add(creator) == Some(value), "fee receipt value mismatch");
        Ok(CovenantUtxoRow {
            covenant_id_hex: r.get("covenant_id_hex"),
            script_hash_hex: r.get("script_hash_hex"),
            address: r.get("address"), txid_hex: r.get("txid_hex"), vout: r.get("vout"),
            amount_sompi: value, amount_sompi_exact: value.to_string(),
            state: Some(state), status: r.get("status"),
            spent_by_txid_hex: r.get("spent_by_txid_hex"),
        })
    }).collect::<Result<Vec<_>>>()?;
    Ok(Kcc20FeeReceiptsPage {
        receipts,
        total_count: summary.get("total_count"),
        protocol_claimable_sompi: summary.get("protocol_total"),
        creator_claimable_sompi: summary.get("creator_total"),
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FomoRoundRow {
    pub covenant_id_hex: String,
    pub script_hash_hex: String,
    pub address: String,
    pub status: String,
    pub pot_sompi: Option<String>,
    pub active_txid_hex: Option<String>,
    pub active_vout: Option<i32>,
    pub state: Option<Value>,
    pub last_buyer: Option<String>,
    pub end_time_ms: Option<String>,
    pub ticket_count: Option<String>,
    pub buy_count: i64,
    pub settled_txid_hex: Option<String>,
    pub created_at_ms: i64,
    pub last_action_time_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantTemplateSummaryRow {
    pub template: String,
    pub covenant_count: i64,
    pub verified_count: i64,
    pub claimed_only_count: i64,
    pub active_covenants: i64,
    pub active_utxos: i64,
    pub total_amount_sompi: String,
    pub action_count: i64,
    pub matched_count: i64,
    pub unrevealed_count: i64,
    pub unmatched_count: i64,
    pub latest_created_at_ms: Option<i64>,
    pub latest_action_time_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20HolderRow {
    pub covenant_id_hex: String,
    pub owner_identifier: String,
    pub identifier_type: i16,
    pub identifier_type_name: String,
    pub amount: String,
    pub utxo_count: i32,
    pub is_minter: bool,
    pub last_change_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20ListingRow {
    pub order_id: String,
    pub txid_hex: Option<String>,
    pub vout: Option<i32>,
    pub template_name: Option<String>,
    pub market_side: String,
    pub sale_covenant_id_hex: String,
    pub sale_script_hash_hex: String,
    pub sale_address: String,
    pub token_id_hex: String,
    pub seller: Option<String>,
    pub token_amount: Option<String>,
    pub price_sompi: Option<String>,
    pub unit_price_sompi: Option<String>,
    pub min_fill_amount: Option<String>,
    pub fee_ticket_id: Option<String>,
    pub status: String,
    pub close_txid_hex: Option<String>,
    pub close_entrypoint: Option<String>,
    pub sale_utxos: i64,
    pub locked_token_utxos: i64,
    pub locked_token_amount: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20BidRow {
    pub order_id: String,
    pub txid_hex: Option<String>,
    pub vout: Option<i32>,
    pub template_name: Option<String>,
    pub market_side: String,
    pub bid_covenant_id_hex: String,
    pub bid_script_hash_hex: String,
    pub bid_address: String,
    pub token_id_hex: String,
    pub buyer: Option<String>,
    pub token_amount: Option<String>,
    pub price_sompi: Option<String>,
    pub unit_price_sompi: Option<String>,
    pub min_fill_amount: Option<String>,
    pub fee_ticket_id: Option<String>,
    pub status: String,
    pub close_txid_hex: Option<String>,
    pub close_entrypoint: Option<String>,
    pub bid_utxos: i64,
    pub bid_value_sompi: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20OwnerOrderRow {
    pub order_id: String,
    pub side: String,
    pub status: String,
    pub token_id_hex: String,
    pub owner: Option<String>,
    pub token_amount: Option<String>,
    pub remaining_token_amount: Option<String>,
    pub price_sompi: Option<String>,
    pub unit_price_sompi: Option<String>,
    pub min_fill_amount: Option<String>,
    pub template_name: Option<String>,
    pub address: String,
    pub txid_hex: Option<String>,
    pub vout: Option<i32>,
    pub close_txid_hex: Option<String>,
    pub close_entrypoint: Option<String>,
    pub created_at_ms: i64,
}

fn kcc20_owner_order_from_row(r: PgRow) -> Kcc20OwnerOrderRow {
    Kcc20OwnerOrderRow {
        order_id: r.get("order_id"),
        side: r.get("side"),
        status: r.get("status"),
        token_id_hex: r.get("token_id_hex"),
        owner: r.get("owner"),
        token_amount: r.get("token_amount"),
        remaining_token_amount: r.get("remaining_token_amount"),
        price_sompi: r.get("price_sompi"),
        unit_price_sompi: r.get("unit_price_sompi"),
        min_fill_amount: r.get("min_fill_amount"),
        template_name: r.get("template_name"),
        address: r.get("address"),
        txid_hex: r.get("txid_hex"),
        vout: r.get("vout"),
        close_txid_hex: r.get("close_txid_hex"),
        close_entrypoint: r.get("close_entrypoint"),
        created_at_ms: r.get("created_at_ms"),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20TradeRow {
    pub token_id_hex: String,
    pub txid_hex: String,
    pub block_time_ms: i64,
    pub entrypoint: Option<String>,
    pub side: String,
    pub maker: Option<String>,
    pub taker: Option<String>,
    pub token_amount: Option<String>,
    pub unit_price_sompi: Option<String>,
    pub price_sompi: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20TradeSummaryRow {
    pub token_id_hex: String,
    pub total_volume_sompi: String,
    pub total_trades: i64,
    pub last_trade_txid_hex: Option<String>,
    pub last_trade_time_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20TokenStatsRow {
    pub token_id_hex: String,
    pub window_ms: i64,
    pub volume_sompi: String,
    pub token_volume: String,
    pub trade_count: i64,
    pub open_unit_price_sompi: Option<String>,
    pub high_unit_price_sompi: Option<String>,
    pub low_unit_price_sompi: Option<String>,
    pub close_unit_price_sompi: Option<String>,
    pub price_change_sompi: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20CandleRow {
    pub token_id_hex: String,
    pub bucket_time_ms: i64,
    pub open_unit_price_sompi: Option<String>,
    pub high_unit_price_sompi: Option<String>,
    pub low_unit_price_sompi: Option<String>,
    pub close_unit_price_sompi: Option<String>,
    pub volume_sompi: String,
    pub token_volume: String,
    pub trade_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20ActivityRow {
    pub event_id: Option<String>,
    pub token_id_hex: String,
    pub txid_hex: String,
    pub block_time_ms: i64,
    pub kind: String,
    pub side: Option<String>,
    pub order_id: Option<String>,
    pub owner: Option<String>,
    pub owner_identifier_type: Option<i16>,
    pub token_amount: Option<String>,
    pub unit_price_sompi: Option<String>,
    pub price_sompi: Option<String>,
    pub entrypoint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Kcc20ActivityFilter {
    pub kind: Option<String>,
    pub scope: Option<String>,
    pub side: Option<String>,
    pub entrypoint: Option<String>,
    pub owner: Option<String>,
    pub txid: Option<String>,
    pub order_id: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20MarketDiscoveryRow {
    pub token_id_hex: String,
    pub best_ask_unit_price_sompi: Option<String>,
    pub best_bid_unit_price_sompi: Option<String>,
    pub spread_sompi: Option<String>,
    pub open_ask_count: i64,
    pub open_bid_count: i64,
    pub total_volume_sompi: String,
    pub total_trades: i64,
    pub volume_24h_sompi: String,
    pub volume_7d_sompi: String,
    pub trade_count_24h: i64,
    pub trade_count_7d: i64,
    pub last_trade_txid_hex: Option<String>,
    pub last_trade_time_ms: Option<i64>,
    pub refreshed_at_ms: i64,
    pub source_blue_score: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20MarketDiscoveryFreshness {
    pub refreshed_at_ms: Option<i64>,
    pub source_blue_score: Option<i64>,
    pub row_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20WrapperSummaryRow {
    pub wrapper_id_hex: String,
    pub market_id_hex: String,
    pub canonical_token_id: String,
    pub claimed_canonical_token_id: Option<String>,
    pub contract_canonical_token_id: Option<String>,
    pub address: Option<String>,
    pub genesis_txid_hex: Option<String>,
    pub active_utxos: i64,
    pub pending_reveal: bool,
    pub enabled: bool,
    pub fee_ticket_id: Option<String>,
    pub wrapped_root_amount: Option<String>,
    pub classification_kind: Option<String>,
    pub classification_status: Option<String>,
    pub claim_source: Option<String>,
    pub refreshed_at_ms: i64,
    pub source_blue_score: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20FeeMarketDiscoveryRow {
    pub market_id_hex: String,
    pub canonical_token_id: String,
    pub address: String,
    pub wrapper_template: String,
    pub genesis_txid_hex: Option<String>,
    pub active_utxos: i64,
    pub enabled: bool,
    pub fee_ticket_id: String,
    pub source_blue_score: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20TokenSummaryRow {
    pub token_id_hex: String,
    pub holder_count: i64,
    pub holder_supply: String,
    pub remaining_supply: String,
    pub active_mint_policy_value: Option<i16>,
    pub public_mint_active: Option<bool>,
    pub wrapper_reserve_supply: String,
    pub orderbook_tradeable_supply: String,
    pub top_holders: Value,
    pub wrapper_id_hex: Option<String>,
    pub refreshed_at_ms: i64,
    pub source_blue_score: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20FastFreshness {
    pub ok: bool,
    pub suggested_poll_ms: i64,
    pub stale: bool,
    pub scanner: ScannerHealth,
    pub projections: Kcc20ProjectionFreshness,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20ProjectionStateFreshness {
    pub name: String,
    pub last_dirty_id: i64,
    pub refreshed_at_ms: Option<i64>,
    pub pending: bool,
    pub pending_age_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20ProjectionFreshness {
    pub latest_dirty_id: i64,
    pub latest_dirty_at_ms: Option<i64>,
    pub market: Kcc20ProjectionStateFreshness,
    pub token_page: Kcc20ProjectionStateFreshness,
    pub activity_feed: Kcc20ProjectionStateFreshness,
    pub owner_orders: Kcc20ProjectionStateFreshness,
    pub owner_portfolio_assets: Kcc20ProjectionStateFreshness,
}

#[derive(Debug, Clone)]
pub struct Kcc20MarketDiscoveryPage {
    pub items: Vec<Kcc20MarketDiscoveryRow>,
    pub total: Option<i64>,
    pub freshness: Kcc20MarketDiscoveryFreshness,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20BalanceRow {
    pub token_id_hex: String,
    pub owner_identifier: String,
    pub identifier_type: i16,
    pub identifier_type_name: String,
    pub amount: String,
    pub utxo_count: i32,
    pub is_minter: bool,
    pub last_change_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20PortfolioRow {
    pub canonical_token_id_hex: String,
    pub native_balance: String,
    pub utxo_count: i64,
    pub last_change_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orderbook_balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_markets: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserve_rows: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20PortfolioAssetActionAvailability {
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20PortfolioAssetActions {
    pub wrap: Kcc20PortfolioAssetActionAvailability,
    pub unwrap: Kcc20PortfolioAssetActionAvailability,
    pub trade: Kcc20PortfolioAssetActionAvailability,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20PortfolioAssetRow {
    pub canonical_token_id_hex: String,
    pub wrapper_id_hex: Option<String>,
    pub wrapped_market_id_hex: Option<String>,
    pub native_balance: String,
    pub orderbook_balance: String,
    pub total_balance: String,
    pub asset_utxo_count: i64,
    pub open_ask_amount: String,
    pub open_bid_amount: String,
    pub open_order_count: i64,
    pub best_ask_unit_price_sompi: Option<String>,
    pub best_bid_unit_price_sompi: Option<String>,
    pub value_sompi: Option<String>,
    pub fee_ticket_supported: bool,
    pub last_change_ms: i64,
    pub ticker: Option<String>,
    pub token_name: Option<String>,
    pub decimals: i16,
    pub actions: Kcc20PortfolioAssetActions,
}

#[derive(Debug, Clone)]
pub struct Kcc20PortfolioAssetOptions {
    pub token_id_hex: Option<String>,
    pub search: Option<String>,
    pub has_native_balance: bool,
    pub has_orderbook_balance: bool,
    pub has_open_orders: bool,
    pub sort_by: String,
    pub sort_direction: String,
    pub limit: i64,
    pub offset: i64,
}

impl Default for Kcc20PortfolioAssetOptions {
    fn default() -> Self {
        Self {
            token_id_hex: None,
            search: None,
            has_native_balance: false,
            has_orderbook_balance: false,
            has_open_orders: false,
            sort_by: "canonicalTokenIdHex".to_string(),
            sort_direction: "asc".to_string(),
            limit: 10,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Kcc20PortfolioAssetPage {
    pub items: Vec<Kcc20PortfolioAssetRow>,
    pub total: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Kcc20PortfolioOptions {
    pub include_wrapped: bool,
    pub include_reserves: bool,
    pub include_totals: bool,
    pub include_empty: bool,
    pub limit: i64,
    pub offset: i64,
}

impl Default for Kcc20PortfolioOptions {
    fn default() -> Self {
        Self {
            include_wrapped: false,
            include_reserves: false,
            include_totals: false,
            include_empty: false,
            limit: 200,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20OwnerActionRow {
    pub owner: Option<String>,
    pub action: String,
    pub txid_hex: String,
    pub block_time_ms: i64,
    pub token_id: Option<String>,
    pub canonical_token_id: Option<String>,
    pub wrapped_token_id: Option<String>,
    pub amount: Option<String>,
    pub direction: Option<String>,
    pub status: String,
    pub input_outpoints: Value,
    pub output_outpoints: Value,
    pub covenant_id_hex: String,
    pub wrapper_covenant_id: Option<String>,
    pub entrypoint: Option<String>,
    pub template_name: Option<String>,
}

/// All covenants the watcher has seen so far, newest first. Uses
/// `covenant_summaries` for active counts and current address so broad list
/// pages do not aggregate raw UTXOs on every request.
///
/// `template_filter` matches against `template_name` (verified) OR
/// `claimed_template` (wallet-declared), unless `verified_only` is set in
/// which case only the verified column counts. `None` template_filter
/// returns every covenant.
pub async fn list_covenant_summaries_paged(
    pool: &PgPool,
    template_filter: Option<&str>,
    verified_only: bool,
    classification_filter: Option<&str>,
    classification_status_filter: Option<&str>,
    claim_arg_filter: Option<&str>,
    claim_arg_value_filter: Option<&str>,
    wallet_filter: Option<&str>,
    wallet_arg_filter: Option<&str>,
    covenant_id_filter: Option<&str>,
    search: Option<&str>,
    active: Option<bool>,
    sort: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(Vec<CovenantSummaryRow>, i64)> {
    list_covenant_summaries_paged_with_aliases(
        pool,
        template_filter,
        verified_only,
        classification_filter,
        classification_status_filter,
        claim_arg_filter,
        claim_arg_value_filter,
        wallet_filter,
        &[],
        wallet_arg_filter,
        covenant_id_filter,
        search,
        &[],
        active,
        sort,
        limit,
        offset,
    )
    .await
}

pub async fn list_covenant_summaries_paged_with_aliases(
    pool: &PgPool,
    template_filter: Option<&str>,
    verified_only: bool,
    classification_filter: Option<&str>,
    classification_status_filter: Option<&str>,
    claim_arg_filter: Option<&str>,
    claim_arg_value_filter: Option<&str>,
    wallet_filter: Option<&str>,
    wallet_filter_aliases: &[String],
    wallet_arg_filter: Option<&str>,
    covenant_id_filter: Option<&str>,
    search: Option<&str>,
    search_aliases: &[String],
    active: Option<bool>,
    sort: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(Vec<CovenantSummaryRow>, i64)> {
    let covenant_id_filter_active = covenant_id_filter.is_some();
    let covenant_id_filter = covenant_id_filter
        .and_then(|hex| hex::decode(hex).ok())
        .filter(|bytes| bytes.len() == 32)
        .unwrap_or_default();
    // Whitelisted sort keys → fixed ORDER BY fragments. Never interpolate
    // caller input; only these constant strings reach the query.
    let order_by = match sort.unwrap_or("recent") {
        "active" => "p.active_utxos DESC, p.created_at_ms DESC, p.covenant_id ASC",
        "amount" => "p.total_amount_sompi DESC, p.created_at_ms DESC, p.covenant_id ASC",
        "template" => "p.template_sort ASC, p.created_at_ms DESC, p.covenant_id ASC",
        _ => "p.created_at_ms DESC, p.covenant_id ASC",
    };
    let wallet_filter_values = normalized_filter_values(wallet_filter, wallet_filter_aliases);
    let wallet_filter_active = !wallet_filter_values.is_empty();
    let search_alias_values = normalized_filter_values(None, search_aliases);
    let search_alias_active = !search_alias_values.is_empty();
    let sql = format!(
        r#"
        WITH wallet_participant_roles(role) AS (
            VALUES
                ('owner'),
                ('owneraddress'),
                ('ownerpubkey'),
                ('owneridentifier'),
                ('ownerkey'),
                ('stateowner'),
                ('stateowneraddress'),
                ('stateownerpubkey'),
                ('wallet'),
                ('walletaddress'),
                ('walletpubkey'),
                ('deployer'),
                ('deployeraddress'),
                ('deployerpubkey'),
                ('seller'),
                ('selleraddress'),
                ('sellerpubkey'),
                ('buyer'),
                ('buyeraddress'),
                ('buyerpubkey'),
                ('signer'),
                ('signeraddress'),
                ('signerpubkey'),
                ('signer1'),
                ('signer2'),
                ('signer3'),
                ('key'),
                ('key1'),
                ('key2'),
                ('key3'),
                ('recovery'),
                ('recoverykey'),
                ('recoveryaddress'),
                ('heir'),
                ('heiraddress'),
                ('arbiter'),
                ('arbiteraddress'),
                ('arbitrator'),
                ('arbitratoraddress'),
                ('beneficiary'),
                ('beneficiaryaddress'),
                ('recipient'),
                ('recipientaddress'),
                ('recipientpubkey'),
                ('sender'),
                ('senderaddress'),
                ('senderpubkey'),
                ('payer'),
                ('payeraddress'),
                ('payerpubkey'),
                ('payee'),
                ('payeeaddress'),
                ('payeepubkey'),
                ('client'),
                ('clientaddress'),
                ('clientpubkey'),
                ('facilitator'),
                ('facilitatoraddress'),
                ('facilitatorpubkey'),
                ('treasury'),
                ('treasuryrecipient'),
                ('protocolfeerecipient'),
                ('hotkey'),
                ('hotwallet'),
                ('hotwalletaddress'),
                ('coldkey'),
                ('coldwallet'),
                ('coldwalletaddress'),
                ('whitelisteddestinations'),
                ('whitelisteddestination'),
                ('destination'),
                ('destinationaddress')
        ),
        wallet_filter_values(value, value_hash) AS (
            SELECT value, md5(value)
            FROM unnest($8::TEXT[]) AS value
        ),
        search_alias_values(value, value_hash) AS (
            SELECT value, md5(value)
            FROM unnest($14::TEXT[]) AS value
        ),
        filtered AS MATERIALIZED (
        SELECT
            c.covenant_id,
            c.created_at_ms,
            COALESCE(s.active_utxos, 0)::bigint AS active_utxos,
            COALESCE(s.total_amount_sompi, 0)::bigint AS total_amount_sompi,
            COALESCE(c.template_name, c.claimed_template, 'Unknown') AS template_sort
        FROM covenants c
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        WHERE
            (
                $1::TEXT IS NULL
                OR ($2::BOOLEAN AND c.template_name = $1)
                -- Match the same label the /covenant-templates dropdown shows:
                -- template_name, else claimed_template, else the literal 'Unknown'
                -- (covenants with neither). Keeps filter results == dropdown labels.
                OR (NOT $2::BOOLEAN AND COALESCE(c.template_name, c.claimed_template, 'Unknown') = $1)
            )
            -- When verified_only is set without a template filter, hide rows that
            -- only have wallet-declared claims and no verified reveal/template yet.
            AND (NOT $2::BOOLEAN OR c.template_name IS NOT NULL)
            AND ($3::TEXT IS NULL OR c.classification_kind = $3)
            AND ($4::TEXT IS NULL OR c.classification_status = $4)
            AND (
                $5::TEXT IS NULL
                OR EXISTS (
                    SELECT 1
                    FROM covenant_participants p
                    WHERE p.covenant_id = c.covenant_id
                      AND p.source = 'claimed_args'
                      AND p.name = lower(btrim($5))
                      AND (
                          $6::TEXT IS NULL
                          OR (
                              p.value_hash = md5(lower(btrim($6)))
                              AND p.value_normalized = lower(btrim($6))
                          )
                      )
                )
            )
            AND (
                NOT $7::BOOLEAN
                OR c.address = ANY($8::TEXT[])
                OR s.current_address = ANY($8::TEXT[])
                OR EXISTS (
                    SELECT 1
                    FROM covenant_participants p
                    WHERE (
                        ($9::TEXT IS NOT NULL AND p.name = lower(btrim($9)))
                        OR (
                            $9::TEXT IS NULL
                            AND (
                                p.name IN (SELECT role FROM wallet_participant_roles)
                                OR lower(btrim(COALESCE(p.type, ''))) IN ('address', 'address[]', 'pubkey', 'pubkey[]')
                                OR lower(btrim(COALESCE(p.type, ''))) LIKE '%address%'
                                OR lower(btrim(COALESCE(p.type, ''))) LIKE '%pubkey%'
                            )
                        )
                    )
                    AND p.covenant_id = c.covenant_id
                    AND EXISTS (
                        SELECT 1
                        FROM wallet_filter_values wf
                        WHERE wf.value_hash = p.value_hash
                          AND wf.value = p.value_normalized
                    )
                )
            )
            AND (
                NOT $10::BOOLEAN
                OR c.covenant_id = $11
                OR c.script_hash = $11
            )
            AND (
                $12::TEXT IS NULL
                OR encode(c.covenant_id, 'hex')  ILIKE '%' || $12 || '%'
                OR encode(c.script_hash, 'hex')  ILIKE '%' || $12 || '%'
                OR encode(c.genesis_txid, 'hex') ILIKE '%' || $12 || '%'
                OR c.address                     ILIKE '%' || $12 || '%'
                OR s.current_address             ILIKE '%' || $12 || '%'
                OR EXISTS (
                    SELECT 1
                    FROM covenant_utxos u
                    WHERE u.covenant_id = c.covenant_id
                      AND u.address = $12
                )
                OR c.template_name               ILIKE '%' || $12 || '%'
                OR c.claimed_template            ILIKE '%' || $12 || '%'
                OR c.classification_kind         ILIKE '%' || $12 || '%'
                OR c.classification_status       ILIKE '%' || $12 || '%'
                OR c.claim_source                ILIKE '%' || $12 || '%'
                OR (
                    $13::BOOLEAN
                    AND EXISTS (
                        SELECT 1
                        FROM covenant_participants p
                        JOIN search_alias_values sf
                          ON sf.value_hash = p.value_hash
                         AND sf.value = p.value_normalized
                        WHERE p.covenant_id = c.covenant_id
                    )
                )
                OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(
                        CASE
                            WHEN jsonb_typeof(c.claimed_args->'args') = 'array' THEN c.claimed_args->'args'
                            ELSE '[]'::jsonb
                        END
                    ) AS arg
                    WHERE arg->>'name' ILIKE '%' || $12 || '%'
                       OR arg->>'value' ILIKE '%' || $12 || '%'
                       OR ($13::BOOLEAN AND lower(arg->>'value') = ANY($14::TEXT[]))
                )
                OR EXISTS (
                    SELECT 1
                    FROM jsonb_each_text(
                        CASE
                            WHEN jsonb_typeof(c.constructor_args) = 'object' THEN c.constructor_args
                            ELSE '{{}}'::jsonb
                        END
                    ) AS arg(name, value)
                    WHERE arg.name ILIKE '%' || $12 || '%'
                       OR arg.value ILIKE '%' || $12 || '%'
                       OR ($13::BOOLEAN AND lower(arg.value) = ANY($14::TEXT[]))
                )
                OR EXISTS (
                    SELECT 1
                    FROM jsonb_each_text(
                        CASE
                            WHEN jsonb_typeof(c.claimed_args) = 'object' THEN c.claimed_args
                            ELSE '{{}}'::jsonb
                        END
                    ) AS arg(name, value)
                    WHERE arg.name ILIKE '%' || $12 || '%'
                       OR arg.value ILIKE '%' || $12 || '%'
                       OR ($13::BOOLEAN AND lower(arg.value) = ANY($14::TEXT[]))
                )
                OR (
                    $13::BOOLEAN
                    AND (
                        c.address = ANY($14::TEXT[])
                        OR s.current_address = ANY($14::TEXT[])
                    )
                )
            )
            AND (
            $15::BOOLEAN IS NULL
            OR ($15 = TRUE  AND COALESCE(s.active_utxos, 0) > 0)
            OR ($15 = FALSE AND COALESCE(s.active_utxos, 0) = 0)
            )
        ),
        page AS (
            SELECT *
            FROM filtered p
            ORDER BY {order_by}
            LIMIT $16 OFFSET COALESCE($17, 0)
        ),
        total AS (
            SELECT COUNT(*)::BIGINT AS total_count
            FROM filtered
        )
        SELECT
            p.covenant_id                      AS page_covenant_id,
            encode(c.covenant_id, 'hex')       AS covenant_id_hex,
            encode(c.script_hash, 'hex')       AS script_hash_hex,
            (c.covenant_id <> c.script_hash)   AS canonical_covenant_id_known,
            CASE
              WHEN c.covenant_id <> c.script_hash THEN 'canonical'
              ELSE 'scriptHashFallback'
            END                                AS identity_source,
            COALESCE(s.current_address, c.address) AS address,
            c.template_name                    AS template,
            c.constructor_args                 AS constructor,
            COALESCE(s.active_utxos, 0)::BIGINT AS active_utxos,
            COALESCE(s.total_amount_sompi, 0)::BIGINT AS total_amount_sompi,
            encode(c.genesis_txid, 'hex')      AS genesis_txid_hex,
            c.created_at_ms                    AS created_at_ms,
            c.claimed_template                 AS claimed_template,
            c.claimed_args                     AS claimed_args,
            c.claim_source                     AS claim_source,
            c.claim_verified                   AS claim_verified,
            c.claim_verified_at_ms             AS claim_verified_at_ms,
            c.classification_kind              AS classification_kind,
            c.classification_status            AS classification_status,
            total.total_count                  AS total_count
        FROM total
        LEFT JOIN page p ON TRUE
        LEFT JOIN covenants c ON c.covenant_id = p.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = p.covenant_id
        ORDER BY {order_by}
        "#
    );
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(template_filter)
        .bind(verified_only)
        .bind(classification_filter)
        .bind(classification_status_filter)
        .bind(claim_arg_filter)
        .bind(claim_arg_value_filter)
        .bind(wallet_filter_active)
        .bind(wallet_filter_values)
        .bind(wallet_arg_filter)
        .bind(covenant_id_filter_active)
        .bind(covenant_id_filter)
        .bind(search)
        .bind(search_alias_active)
        .bind(search_alias_values)
        .bind(active)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    let total: i64 = rows
        .first()
        .map(|r| r.get::<i64, _>("total_count"))
        .unwrap_or(0);
    let summaries: Vec<CovenantSummaryRow> = rows
        .into_iter()
        .filter_map(|r| {
            let page_covenant_id: Option<Vec<u8>> = r.get("page_covenant_id");
            page_covenant_id?;
            let template: Option<String> = r.get("template");
            Some(CovenantSummaryRow {
                inscription_protocol: inscription_protocol_from_template(template.as_deref()),
                covenant_id_hex: r.get("covenant_id_hex"),
                script_hash_hex: r.get("script_hash_hex"),
                canonical_covenant_id_known: r.get("canonical_covenant_id_known"),
                identity_source: r.get("identity_source"),
                address: r.get("address"),
                template,
                constructor: r.get("constructor"),
                active_utxos: r.get("active_utxos"),
                total_amount_sompi: r.get("total_amount_sompi"),
                genesis_txid_hex: r.get("genesis_txid_hex"),
                created_at_ms: r.get("created_at_ms"),
                claimed_template: r.get("claimed_template"),
                claimed_args: r.get("claimed_args"),
                claim_source: r.get("claim_source"),
                claim_verified: r.get("claim_verified"),
                claim_verified_at_ms: r.get("claim_verified_at_ms"),
                classification_kind: r.get("classification_kind"),
                classification_status: r.get("classification_status"),
            })
        })
        .collect();
    Ok((summaries, total))
}

/// Back-compat helper: unpaginated list (every matching covenant), used by
/// callers and tests that don't need a total or a page window.
pub async fn list_covenant_summaries(
    pool: &PgPool,
    template_filter: Option<&str>,
    verified_only: bool,
    classification_filter: Option<&str>,
    classification_status_filter: Option<&str>,
    claim_arg_filter: Option<&str>,
    claim_arg_value_filter: Option<&str>,
) -> Result<Vec<CovenantSummaryRow>> {
    let (rows, _total) = list_covenant_summaries_paged(
        pool,
        template_filter,
        verified_only,
        classification_filter,
        classification_status_filter,
        claim_arg_filter,
        claim_arg_value_filter,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await?;
    Ok(rows)
}

/// One covenant by canonical `covenant_id` or legacy `script_hash`.
pub async fn covenant_by_script_hash(
    pool: &PgPool,
    script_hash_hex: &str,
) -> Result<Option<CovenantSummaryRow>> {
    let raw = crate::persist::identity::resolve_alias(pool, &hex::decode(script_hash_hex)?).await?;
    let row = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex')   AS covenant_id_hex,
            encode(c.script_hash, 'hex')    AS script_hash_hex,
            (c.covenant_id <> c.script_hash) AS canonical_covenant_id_known,
            CASE
              WHEN c.covenant_id <> c.script_hash THEN 'canonical'
              ELSE 'scriptHashFallback'
            END                              AS identity_source,
            COALESCE(s.current_address, c.address) AS address,
            c.template_name                  AS template,
            c.constructor_args               AS constructor,
            COALESCE(s.active_utxos, 0)::bigint AS active_utxos,
            COALESCE(s.total_amount_sompi, 0)::bigint AS total_amount_sompi,
            encode(c.genesis_txid, 'hex')   AS genesis_txid_hex,
            c.created_at_ms                  AS created_at_ms,
            c.claimed_template               AS claimed_template,
            c.claimed_args                   AS claimed_args,
            c.claim_source                   AS claim_source,
            c.claim_verified                 AS claim_verified,
            c.claim_verified_at_ms           AS claim_verified_at_ms,
            c.classification_kind            AS classification_kind,
            c.classification_status          AS classification_status
        FROM covenants c
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        WHERE (c.covenant_id = $1 OR c.script_hash = $1)
        ORDER BY (c.covenant_id = $1) DESC, c.created_at_ms DESC
        LIMIT 1
        "#,
    )
    .bind(raw)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let template: Option<String> = r.get("template");
        CovenantSummaryRow {
            inscription_protocol: inscription_protocol_from_template(template.as_deref()),
            covenant_id_hex: r.get("covenant_id_hex"),
            script_hash_hex: r.get("script_hash_hex"),
            canonical_covenant_id_known: r.get("canonical_covenant_id_known"),
            identity_source: r.get("identity_source"),
            address: r.get("address"),
            template,
            constructor: r.get("constructor"),
            active_utxos: r.get("active_utxos"),
            total_amount_sompi: r.get("total_amount_sompi"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            created_at_ms: r.get("created_at_ms"),
            claimed_template: r.get("claimed_template"),
            claimed_args: r.get("claimed_args"),
            claim_source: r.get("claim_source"),
            claim_verified: r.get("claim_verified"),
            claim_verified_at_ms: r.get("claim_verified_at_ms"),
            classification_kind: r.get("classification_kind"),
            classification_status: r.get("classification_status"),
        }
    }))
}

pub async fn covenants_by_address(pool: &PgPool, address: &str) -> Result<Vec<CovenantSummaryRow>> {
    covenants_by_address_with_aliases(pool, address, &[], 200, 0).await
}

pub async fn covenants_by_address_with_aliases(
    pool: &PgPool,
    address: &str,
    aliases: &[String],
    limit: i64,
    offset: i64,
) -> Result<Vec<CovenantSummaryRow>> {
    let address_values = normalized_filter_values(Some(address), aliases);
    let rows = sqlx::query(
        r#"
        WITH wallet_participant_roles(role) AS (
            VALUES
                ('owner'),
                ('owneraddress'),
                ('ownerpubkey'),
                ('owneridentifier'),
                ('ownerkey'),
                ('stateowner'),
                ('stateowneraddress'),
                ('stateownerpubkey'),
                ('wallet'),
                ('walletaddress'),
                ('walletpubkey'),
                ('deployer'),
                ('deployeraddress'),
                ('deployerpubkey'),
                ('seller'),
                ('selleraddress'),
                ('sellerpubkey'),
                ('buyer'),
                ('buyeraddress'),
                ('buyerpubkey'),
                ('signer'),
                ('signeraddress'),
                ('signerpubkey'),
                ('signer1'),
                ('signer2'),
                ('signer3'),
                ('key'),
                ('key1'),
                ('key2'),
                ('key3'),
                ('recovery'),
                ('recoverykey'),
                ('recoveryaddress'),
                ('heir'),
                ('heiraddress'),
                ('arbiter'),
                ('arbiteraddress'),
                ('arbitrator'),
                ('arbitratoraddress'),
                ('beneficiary'),
                ('beneficiaryaddress'),
                ('recipient'),
                ('recipientaddress'),
                ('recipientpubkey'),
                ('sender'),
                ('senderaddress'),
                ('senderpubkey'),
                ('payer'),
                ('payeraddress'),
                ('payerpubkey'),
                ('payee'),
                ('payeeaddress'),
                ('payeepubkey'),
                ('client'),
                ('clientaddress'),
                ('clientpubkey'),
                ('facilitator'),
                ('facilitatoraddress'),
                ('facilitatorpubkey'),
                ('treasury'),
                ('treasuryrecipient'),
                ('protocolfeerecipient'),
                ('hotkey'),
                ('hotwallet'),
                ('hotwalletaddress'),
                ('coldkey'),
                ('coldwallet'),
                ('coldwalletaddress'),
                ('whitelisteddestinations'),
                ('whitelisteddestination'),
                ('destination'),
                ('destinationaddress')
        ),
        address_values(value, value_hash) AS (
            SELECT value, md5(value)
            FROM unnest($1::TEXT[]) AS value
        )
        SELECT
            encode(c.covenant_id, 'hex')   AS covenant_id_hex,
            encode(c.script_hash, 'hex')    AS script_hash_hex,
            (c.covenant_id <> c.script_hash) AS canonical_covenant_id_known,
            CASE
              WHEN c.covenant_id <> c.script_hash THEN 'canonical'
              ELSE 'scriptHashFallback'
            END                              AS identity_source,
            COALESCE(s.current_address, c.address) AS address,
            c.template_name                  AS template,
            c.constructor_args               AS constructor,
            COALESCE(s.active_utxos, 0)::bigint AS active_utxos,
            COALESCE(s.total_amount_sompi, 0)::bigint AS total_amount_sompi,
            encode(c.genesis_txid, 'hex')   AS genesis_txid_hex,
            c.created_at_ms                  AS created_at_ms,
            c.claimed_template               AS claimed_template,
            c.claimed_args                   AS claimed_args,
            c.claim_source                   AS claim_source,
            c.claim_verified                 AS claim_verified,
            c.claim_verified_at_ms           AS claim_verified_at_ms,
            c.classification_kind            AS classification_kind,
            c.classification_status          AS classification_status
        FROM covenants c
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        WHERE c.address = ANY($1::TEXT[])
           OR s.current_address = ANY($1::TEXT[])
           OR EXISTS (
               SELECT 1
               FROM covenant_participants p
               JOIN address_values av
                 ON av.value_hash = p.value_hash
                AND av.value = p.value_normalized
               WHERE p.covenant_id = c.covenant_id
                 AND (
                     p.name IN (SELECT role FROM wallet_participant_roles)
                     OR lower(btrim(COALESCE(p.type, ''))) IN ('address', 'address[]', 'pubkey', 'pubkey[]')
                     OR lower(btrim(COALESCE(p.type, ''))) LIKE '%address%'
                     OR lower(btrim(COALESCE(p.type, ''))) LIKE '%pubkey%'
                 )
           )
        ORDER BY c.created_at_ms DESC, c.covenant_id ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(address_values)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let template: Option<String> = r.get("template");
            CovenantSummaryRow {
                inscription_protocol: inscription_protocol_from_template(template.as_deref()),
                covenant_id_hex: r.get("covenant_id_hex"),
                script_hash_hex: r.get("script_hash_hex"),
                canonical_covenant_id_known: r.get("canonical_covenant_id_known"),
                identity_source: r.get("identity_source"),
                address: r.get("address"),
                template,
                constructor: r.get("constructor"),
                active_utxos: r.get("active_utxos"),
                total_amount_sompi: r.get("total_amount_sompi"),
                genesis_txid_hex: r.get("genesis_txid_hex"),
                created_at_ms: r.get("created_at_ms"),
                claimed_template: r.get("claimed_template"),
                claimed_args: r.get("claimed_args"),
                claim_source: r.get("claim_source"),
                claim_verified: r.get("claim_verified"),
                claim_verified_at_ms: r.get("claim_verified_at_ms"),
                classification_kind: r.get("classification_kind"),
                classification_status: r.get("classification_status"),
            }
        })
        .collect())
}

pub async fn covenants_by_address_count(
    pool: &PgPool,
    address: &str,
    aliases: &[String],
) -> Result<i64> {
    let address_values = normalized_filter_values(Some(address), aliases);
    let count = sqlx::query_scalar(
        r#"
        WITH wallet_participant_roles(role) AS (
            VALUES
                ('owner'), ('owneraddress'), ('ownerpubkey'), ('owneridentifier'),
                ('ownerkey'), ('stateowner'), ('stateowneraddress'), ('stateownerpubkey'),
                ('wallet'), ('walletaddress'), ('walletpubkey'), ('deployer'),
                ('deployeraddress'), ('deployerpubkey'), ('seller'), ('selleraddress'),
                ('sellerpubkey'), ('buyer'), ('buyeraddress'), ('buyerpubkey'),
                ('signer'), ('signeraddress'), ('signerpubkey'), ('signer1'), ('signer2'),
                ('signer3'), ('key'), ('key1'), ('key2'), ('key3'), ('recovery'),
                ('recoverykey'), ('recoveryaddress'), ('heir'), ('heiraddress'),
                ('arbiter'), ('arbiteraddress'), ('arbitrator'), ('arbitratoraddress'),
                ('beneficiary'), ('beneficiaryaddress'), ('recipient'), ('recipientaddress'),
                ('recipientpubkey'), ('sender'), ('senderaddress'), ('senderpubkey'),
                ('payer'), ('payeraddress'), ('payerpubkey'), ('payee'), ('payeeaddress'),
                ('payeepubkey'), ('client'), ('clientaddress'), ('clientpubkey'),
                ('facilitator'), ('facilitatoraddress'), ('facilitatorpubkey'), ('treasury'),
                ('treasuryrecipient'), ('protocolfeerecipient'), ('hotkey'), ('hotwallet'),
                ('hotwalletaddress'), ('coldkey'), ('coldwallet'), ('coldwalletaddress'),
                ('whitelisteddestinations'), ('whitelisteddestination'), ('destination'),
                ('destinationaddress')
        ),
        address_values(value, value_hash) AS (
            SELECT value, md5(value)
            FROM unnest($1::TEXT[]) AS value
        )
        SELECT COUNT(*)::BIGINT
        FROM covenants c
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        WHERE c.address = ANY($1::TEXT[])
           OR s.current_address = ANY($1::TEXT[])
           OR EXISTS (
               SELECT 1
               FROM covenant_participants p
               JOIN address_values av
                 ON av.value_hash = p.value_hash
                AND av.value = p.value_normalized
               WHERE p.covenant_id = c.covenant_id
                 AND (
                     p.name IN (SELECT role FROM wallet_participant_roles)
                     OR lower(btrim(COALESCE(p.type, ''))) IN ('address', 'address[]', 'pubkey', 'pubkey[]')
                     OR lower(btrim(COALESCE(p.type, ''))) LIKE '%address%'
                     OR lower(btrim(COALESCE(p.type, ''))) LIKE '%pubkey%'
                 )
           )
        "#,
    )
    .bind(address_values)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

async fn resolve_covenant_id(
    pool: &PgPool,
    covenant_id_or_script_hash: &[u8],
) -> Result<Option<Vec<u8>>> {
    let resolved = crate::persist::identity::resolve_alias(pool, covenant_id_or_script_hash).await?;
    let covenant_id = sqlx::query_scalar(
        r#"
        SELECT covenant_id
        FROM covenants
        WHERE covenant_id = $1 OR script_hash = $1
        ORDER BY (covenant_id = $1) DESC
        LIMIT 1
        "#,
    )
    .bind(resolved)
    .fetch_optional(pool)
    .await?;
    Ok(covenant_id)
}

/// One page of actions on a covenant (deploys + spends + continuations).
pub async fn actions_for_covenant(
    pool: &PgPool,
    script_hash_hex: &str,
    limit: i64,
    offset: i64,
    descending: bool,
    action: Option<&str>,
    entrypoints: &[String],
) -> Result<Vec<CovenantActionRow>> {
    let raw = hex::decode(script_hash_hex)?;
    let Some(covenant_id) = resolve_covenant_id(pool, &raw).await? else {
        return Ok(Vec::new());
    };
    let direction = if descending { "DESC" } else { "ASC" };
    let statement = format!(
        r#"
        WITH action_page AS MATERIALIZED (
            SELECT *
            FROM covenant_actions
            WHERE covenant_id = $1
              AND ($4::TEXT IS NULL OR action = $4)
              AND (cardinality($5::TEXT[]) = 0 OR entrypoint = ANY($5::TEXT[]))
            ORDER BY block_time_ms {direction}, id {direction}
            LIMIT $2 OFFSET $3
        )
        SELECT
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM action_page a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        LEFT JOIN covenant_utxos input_utxo
          ON a.action = 'spend'
         AND NULLIF(a.inputs->>'address', '') IS NULL
         AND input_utxo.txid = CASE
               WHEN a.inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{{64}}$'
               THEN decode(a.inputs->'previousOutpoint'->>'hash', 'hex')
             END
         AND input_utxo.vout = CASE
               WHEN a.inputs->'previousOutpoint'->>'index' ~ '^[0-9]+$'
               THEN (a.inputs->'previousOutpoint'->>'index')::INT
             END
        ORDER BY a.block_time_ms {direction}, a.id {direction}
        "#
    );
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(AssertSqlSafe(statement))
        .bind(covenant_id)
        .bind(limit)
        .bind(offset)
        .bind(action)
        .bind(entrypoints)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(rows.into_iter().map(action_row_from_sql).collect())
}

pub async fn actions_for_covenant_count(
    pool: &PgPool,
    script_hash_hex: &str,
    action: Option<&str>,
    entrypoints: &[String],
) -> Result<i64> {
    let raw = hex::decode(script_hash_hex)?;
    let Some(covenant_id) = resolve_covenant_id(pool, &raw).await? else {
        return Ok(0);
    };
    if action.is_none() && entrypoints.is_empty() {
        let count = sqlx::query_scalar(
            "SELECT action_count FROM covenant_action_summaries WHERE covenant_id = $1",
        )
        .bind(&covenant_id)
        .fetch_optional(pool)
        .await?;
        if let Some(count) = count {
            return Ok(count);
        }
    }
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let count = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM covenant_actions a
        WHERE a.covenant_id = $1
          AND ($2::TEXT IS NULL OR a.action = $2)
          AND (cardinality($3::TEXT[]) = 0 OR a.entrypoint = ANY($3::TEXT[]))
        "#,
    )
    .bind(covenant_id)
    .bind(action)
    .bind(entrypoints)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

pub async fn snapshot_claim_actions(
    pool: &PgPool,
    controller_id_hex: &str,
    token_id_hex: &str,
    limit: i64,
    offset: i64,
) -> Result<SnapshotClaimActionPage> {
    let raw_controller = hex::decode(controller_id_hex)?;
    let raw_token = hex::decode(token_id_hex)?;
    if raw_controller.len() != 32 || raw_token.len() != 32 {
        anyhow::bail!("snapshot controller and token IDs must be exactly 32 bytes");
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(
        r#"
        WITH claim_page AS MATERIALIZED (
            SELECT *
            FROM covenant_actions
            WHERE covenant_id = $1
              AND action = 'spend'
              AND entrypoint = 'claim'
              AND decoded_args->>'projectionSchema' = 'kcc20-snapshot-claim/v1'
              AND lower(decoded_args->>'tokenId') = encode($2, 'hex')
            ORDER BY block_time_ms ASC, id ASC
            LIMIT $3 OFFSET $4
        )
        SELECT
            encode(controller.covenant_id, 'hex') AS controller_id_hex,
            encode(claim.txid, 'hex') AS txid_hex,
            encode(claim.block_hash, 'hex') AS block_hash_hex,
            claim.block_time_ms,
            claim.inputs,
            claim.decoded_args,
            controller.classification_kind,
            controller.classification_status,
            controller.template_name AS controller_template_name,
            token_match.action_count AS token_action_count,
            token_match.inputs AS token_inputs,
            token_match.template_name AS token_template_name,
            token_match.classification_kind AS token_classification_kind,
            token_match.classification_status AS token_classification_status
        FROM claim_page claim
        JOIN covenants controller ON controller.covenant_id = claim.covenant_id
        LEFT JOIN LATERAL (
            SELECT
                COUNT(*)::BIGINT AS action_count,
                CASE WHEN COUNT(*) = 1
                    THEN (ARRAY_AGG(token_action.inputs ORDER BY token_action.id))[1]
                END AS inputs,
                CASE WHEN COUNT(*) = 1
                    THEN (ARRAY_AGG(token_covenant.classification_kind ORDER BY token_action.id))[1]
                END AS classification_kind,
                CASE WHEN COUNT(*) = 1
                    THEN (ARRAY_AGG(token_covenant.classification_status ORDER BY token_action.id))[1]
                END AS classification_status,
                CASE WHEN COUNT(*) = 1
                    THEN (ARRAY_AGG(token_covenant.template_name ORDER BY token_action.id))[1]
                END AS template_name
            FROM covenant_actions token_action
            JOIN covenants token_covenant
              ON token_covenant.covenant_id = token_action.covenant_id
            WHERE token_action.txid = claim.txid
              AND token_action.action = 'spend'
              AND token_action.entrypoint = 'transfer'
              -- Native KCC20 actions use their covenant ID as the token ID.
              -- Prefer the explicit canonical binding when present, and only
              -- fall back to that exact lineage when the optional projection
              -- field is absent. A conflicting explicit binding stays rejected.
              AND (
                  token_action.canonical_token_id = $2
                  OR (
                      token_action.canonical_token_id IS NULL
                      AND token_action.covenant_id = $2
                  )
              )
        ) token_match ON TRUE
        ORDER BY claim.block_time_ms ASC, claim.id ASC
        "#,
    )
    .bind(&raw_controller)
    .bind(&raw_token)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *tx)
    .await?;
    let (total, content_commitment, commitment_present, canonical_claim_exists): (
        i64,
        String,
        bool,
        bool,
    ) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(history.total, 0)::BIGINT,
            encode(
                COALESCE(
                    history.content_commitment,
                    snapshot_claim_history_empty_commitment($1, $2)
                ),
                'hex'
            ),
            history.controller_id IS NOT NULL,
            EXISTS (
                SELECT 1
                FROM covenant_actions claim
                WHERE claim.covenant_id = $1
                  AND claim.action = 'spend'
                  AND claim.entrypoint = 'claim'
                  AND claim.decoded_args->>'projectionSchema' =
                      'kcc20-snapshot-claim/v1'
                  AND snapshot_claim_token_id(claim.decoded_args) = $2
                LIMIT 1
            )
        FROM (VALUES (TRUE)) AS requested(singleton)
        LEFT JOIN snapshot_claim_history_commitments history
          ON history.controller_id = $1
         AND history.token_id = $2
        "#,
    )
    .bind(&raw_controller)
    .bind(&raw_token)
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        commitment_present || !canonical_claim_exists,
        "canonical snapshot claims lack a materialized content commitment"
    );
    let (epoch, revision): (String, i64) = sqlx::query_as(
        "SELECT epoch, revision FROM snapshot_claim_history_revision WHERE singleton = TRUE",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let items = rows
        .into_iter()
        .map(|row| SnapshotClaimActionRow {
            controller_id_hex: row.get("controller_id_hex"),
            txid_hex: row.get("txid_hex"),
            block_hash_hex: row.get("block_hash_hex"),
            block_time_ms: row.get("block_time_ms"),
            inputs: row.get("inputs"),
            decoded_args: row.get("decoded_args"),
            classification_kind: row.get("classification_kind"),
            classification_status: row.get("classification_status"),
            controller_template_name: row.get("controller_template_name"),
            token_action_count: row.get("token_action_count"),
            token_inputs: row.get("token_inputs"),
            token_template_name: row.get("token_template_name"),
            token_classification_kind: row.get("token_classification_kind"),
            token_classification_status: row.get("token_classification_status"),
        })
        .collect();
    Ok(SnapshotClaimActionPage {
        epoch,
        revision,
        total,
        content_commitment,
        items,
    })
}

pub async fn actions_by_address(
    pool: &PgPool,
    address: &str,
    limit: i64,
) -> Result<Vec<CovenantActionRow>> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(
        r#"
        WITH address_covenants AS MATERIALIZED (
            SELECT
                c.covenant_id,
                c.script_hash,
                c.address,
                COALESCE(s.current_address, c.address) AS current_address,
                COALESCE(s.active_utxos, 0) AS active_utxos,
                c.template_name,
                c.classification_kind,
                c.classification_status
            FROM covenants c
            LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
            WHERE c.address = $1 OR s.current_address = $1
        ),
        matched_actions AS (
        (
            SELECT
            a.id                            AS action_id,
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN c.active_utxos = 1 THEN c.current_address
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM address_covenants c
        -- Resolve matching covenant ids first, then fetch recent actions per
        -- covenant id. This prevents Postgres from scanning the global
        -- block-time action index while looking for one covenant address.
        JOIN LATERAL (
            SELECT *
            FROM covenant_actions a
            WHERE a.covenant_id = c.covenant_id
            ORDER BY a.block_time_ms DESC, a.id DESC
            LIMIT $2
        ) a ON TRUE
        LEFT JOIN covenant_utxos input_utxo
          ON a.action = 'spend'
         AND NULLIF(a.inputs->>'address', '') IS NULL
         AND input_utxo.txid = CASE
               WHEN a.inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{64}$'
               THEN decode(a.inputs->'previousOutpoint'->>'hash', 'hex')
             END
         AND input_utxo.vout = CASE
               WHEN a.inputs->'previousOutpoint'->>'index' ~ '^[0-9]+$'
               THEN (a.inputs->'previousOutpoint'->>'index')::INT
             END
        )
        UNION ALL
        (
            SELECT
            a.id                            AS action_id,
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM covenant_actions a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        LEFT JOIN covenant_utxos input_utxo
          ON a.action = 'spend'
         AND NULLIF(a.inputs->>'address', '') IS NULL
         AND input_utxo.txid = CASE
               WHEN a.inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{64}$'
               THEN decode(a.inputs->'previousOutpoint'->>'hash', 'hex')
             END
         AND input_utxo.vout = CASE
               WHEN a.inputs->'previousOutpoint'->>'index' ~ '^[0-9]+$'
               THEN (a.inputs->'previousOutpoint'->>'index')::INT
             END
        WHERE a.outputs ? 'address'
          AND a.outputs->>'address' = $1
          AND CASE
                WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
                ELSE COALESCE(
                    NULLIF(a.outputs->>'address', ''),
                    NULLIF(a.inputs->>'address', ''),
                    input_utxo.address,
                    c.address
                )
              END = $1
          AND NOT EXISTS (
              SELECT 1
              FROM address_covenants ac
              WHERE ac.covenant_id = c.covenant_id
          )
        ORDER BY a.block_time_ms DESC, a.id DESC
        LIMIT $2
        )
        UNION ALL
        (
            SELECT
            a.id                            AS action_id,
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM covenant_utxos input_utxo
        JOIN covenant_actions a
          ON a.covenant_id = input_utxo.covenant_id
         AND a.txid = input_utxo.spent_by_txid
         AND a.action = 'spend'
         AND a.inputs->'previousOutpoint'->>'hash' = encode(input_utxo.txid, 'hex')
         AND a.inputs->'previousOutpoint'->>'index' = input_utxo.vout::TEXT
        JOIN covenants c ON c.covenant_id = a.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        WHERE input_utxo.address = $1
          AND input_utxo.spent_by_txid IS NOT NULL
          AND CASE
                WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
                ELSE COALESCE(
                    NULLIF(a.outputs->>'address', ''),
                    NULLIF(a.inputs->>'address', ''),
                    input_utxo.address,
                    c.address
                )
              END = $1
          AND NOT EXISTS (
              SELECT 1
              FROM address_covenants ac
              WHERE ac.covenant_id = c.covenant_id
          )
        ORDER BY a.block_time_ms DESC, a.id DESC
        LIMIT $2
        )
        )
        SELECT
            covenant_id_hex,
            canonical_token_id_hex,
            script_hash_hex,
            address,
            txid_hex,
            block_hash_hex,
            block_time_ms,
            action,
            entrypoint,
            inputs,
            outputs,
            decoded_args,
            template,
            classification_kind,
            classification_status
        FROM matched_actions
        ORDER BY block_time_ms DESC, action_id DESC
        LIMIT $2
        "#,
    )
    .bind(address)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(rows.into_iter().map(action_row_from_sql).collect())
}

/// All actions whose `txid` matches — used by `/tx/{txid}`. A single tx can
/// touch multiple covenants in principle.
pub async fn actions_by_txid(pool: &PgPool, txid_hex: &str) -> Result<Vec<CovenantActionRow>> {
    actions_by_txid_on(&mut *pool.acquire().await?, txid_hex).await
}

/// Decode completeness and action rows must come from one database snapshot.
pub async fn actions_by_txid_if_decoded(pool: &PgPool, txid_hex: &str) -> Result<Option<Vec<CovenantActionRow>>> {
    let mut conn = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY").execute(&mut *conn).await?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_deferred_decodes WHERE txid=$1 AND status='pending')")
        .bind(hex::decode(txid_hex)?).fetch_one(&mut *conn).await?;
    let actions = if pending { None } else { Some(actions_by_txid_on(&mut conn, txid_hex).await?) };
    conn.commit().await?;
    Ok(actions)
}

async fn actions_by_txid_on(conn: &mut sqlx::PgConnection, txid_hex: &str) -> Result<Vec<CovenantActionRow>> {
    let raw = hex::decode(txid_hex)?;
    let rows = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM covenant_actions a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        LEFT JOIN covenant_utxos input_utxo
          ON a.action = 'spend'
         AND NULLIF(a.inputs->>'address', '') IS NULL
         AND input_utxo.txid = CASE
               WHEN a.inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{64}$'
               THEN decode(a.inputs->'previousOutpoint'->>'hash', 'hex')
             END
         AND input_utxo.vout = CASE
               WHEN a.inputs->'previousOutpoint'->>'index' ~ '^[0-9]+$'
               THEN (a.inputs->'previousOutpoint'->>'index')::INT
             END
        WHERE a.txid = $1
        ORDER BY a.id ASC
        "#,
    )
    .bind(raw)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.into_iter().map(action_row_from_sql).collect())
}

/// Recent actions across all covenants, newest first. Powers `/events`.
pub async fn recent_actions(
    pool: &PgPool,
    limit: i64,
    classification_filter: Option<&str>,
    classification_status_filter: Option<&str>,
) -> Result<Vec<CovenantActionRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(a.canonical_token_id, 'hex') AS canonical_token_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            CASE
              WHEN s.active_utxos = 1 THEN COALESCE(s.current_address, c.address)
              ELSE COALESCE(
                  NULLIF(a.outputs->>'address', ''),
                  NULLIF(a.inputs->>'address', ''),
                  input_utxo.address,
                  c.address
              )
            END AS address,
            encode(a.txid, 'hex')          AS txid_hex,
            encode(a.block_hash, 'hex')    AS block_hash_hex,
            a.block_time_ms                AS block_time_ms,
            a.action                        AS action,
            a.entrypoint                    AS entrypoint,
            a.inputs                        AS inputs,
            a.outputs                       AS outputs,
            a.decoded_args                  AS decoded_args,
            c.template_name                 AS template,
            c.classification_kind           AS classification_kind,
            c.classification_status         AS classification_status
        FROM covenant_actions a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
        LEFT JOIN covenant_utxos input_utxo
          ON a.action = 'spend'
         AND NULLIF(a.inputs->>'address', '') IS NULL
         AND input_utxo.txid = CASE
               WHEN a.inputs->'previousOutpoint'->>'hash' ~ '^[0-9a-fA-F]{64}$'
               THEN decode(a.inputs->'previousOutpoint'->>'hash', 'hex')
             END
         AND input_utxo.vout = CASE
               WHEN a.inputs->'previousOutpoint'->>'index' ~ '^[0-9]+$'
               THEN (a.inputs->'previousOutpoint'->>'index')::INT
             END
        WHERE ($2::TEXT IS NULL OR c.classification_kind = $2)
          AND ($3::TEXT IS NULL OR c.classification_status = $3)
        ORDER BY a.block_time_ms DESC, a.id DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .bind(classification_filter)
    .bind(classification_status_filter)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(action_row_from_sql).collect())
}

fn action_row_from_sql(r: sqlx::postgres::PgRow) -> CovenantActionRow {
    let template: Option<String> = r.get("template");
    let address: String = r.get("address");
    CovenantActionRow {
        inscription_protocol: inscription_protocol_from_template(template.as_deref()),
        covenant_id_hex: r.get("covenant_id_hex"),
        canonical_token_id_hex: r.get("canonical_token_id_hex"),
        script_hash_hex: r.get("script_hash_hex"),
        inputs: action_json_with_current_address(r.get("inputs"), &address),
        outputs: action_json_with_current_address(r.get("outputs"), &address),
        address,
        txid_hex: r.get("txid_hex"),
        block_hash_hex: r.get("block_hash_hex"),
        block_time_ms: r.get("block_time_ms"),
        action: r.get("action"),
        entrypoint: r.get("entrypoint"),
        decoded_args: r.get("decoded_args"),
        classification_kind: r.get("classification_kind"),
        classification_status: r.get("classification_status"),
    }
}

fn action_json_with_current_address(value: Option<Value>, address: &str) -> Option<Value> {
    match value {
        Some(Value::Object(mut object)) => {
            if object.contains_key("address") {
                object.insert("address".to_string(), Value::String(address.to_string()));
            }
            Some(Value::Object(object))
        }
        other => other,
    }
}

fn inscription_protocol_from_template(template: Option<&str>) -> Option<String> {
    let template = template?;
    if template.starts_with("KRC-20-") {
        Some("KRC-20".to_string())
    } else if template.starts_with("KRC-721-") {
        Some("KRC-721".to_string())
    } else if template.starts_with("KNS-") {
        Some("KNS".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        inscription_protocol_from_template, kcc20_activity_feed_projection_name,
        kcc20_activity_refresh_sql, kcc20_market_projection_name, kcc20_owner_orders,
        kcc20_owner_orders_projection_name, kcc20_owner_portfolio_assets_projection_name,
        kcc20_portfolio_asset_actions, kcc20_projection_freshness,
        kcc20_token_page_projection_name, mark_kcc20_projection_refreshed_for,
        prune_kcc20_projection_dirty, refresh_kcc20_owner_orders,
    };
    use crate::PgPool;

    const ACTIVITY_REFRESH_TEMPLATE: &str = r#"
        SELECT 1
        FROM covenant_actions a
        __KCC20_ACTIVITY_REFRESH_SCOPE_JOIN__
        WHERE __KCC20_ACTIVITY_REFRESH_SCOPE_FILTER__
        __KCC20_CROSS_MATCH_DEDUPE_GUARD__
    "#;

    #[test]
    fn scoped_activity_refresh_uses_txid_join_without_window_predicate() {
        let sql = kcc20_activity_refresh_sql(ACTIVITY_REFRESH_TEMPLATE, true);

        assert!(sql.contains("JOIN pending_dirty refresh_scope ON refresh_scope.txid = a.txid"));
        assert!(sql.contains("WHERE TRUE"));
        assert!(!sql.contains("a.block_time_ms >= $1"));
        assert!(!sql.contains("__KCC20_"));
    }

    #[test]
    fn window_activity_refresh_keeps_recent_or_dirty_filter() {
        let sql = kcc20_activity_refresh_sql(ACTIVITY_REFRESH_TEMPLATE, false);

        assert!(!sql.contains("JOIN pending_dirty refresh_scope"));
        assert!(sql.contains("a.block_time_ms >= $1"));
        assert!(sql.contains("WHERE dirty.txid = a.txid"));
        assert!(!sql.contains("__KCC20_"));
    }

    #[test]
    fn derives_inscription_protocol_from_template_name() {
        assert_eq!(
            inscription_protocol_from_template(Some("KRC-20-transfer")).as_deref(),
            Some("KRC-20")
        );
        assert_eq!(
            inscription_protocol_from_template(Some("KRC-721-mint")).as_deref(),
            Some("KRC-721")
        );
        assert_eq!(
            inscription_protocol_from_template(Some("KNS-create")).as_deref(),
            Some("KNS")
        );
        assert_eq!(inscription_protocol_from_template(Some("KCC20")), None);
        assert_eq!(inscription_protocol_from_template(None), None);
    }

    #[test]
    fn portfolio_asset_actions_match_backend_availability_contract() {
        let unavailable = kcc20_portfolio_asset_actions(false, true, true, true);
        assert!(!unavailable.wrap.enabled);
        assert_eq!(
            unavailable.wrap.reason.as_deref(),
            Some("wrapper is not available")
        );
        assert!(!unavailable.unwrap.enabled);
        assert!(!unavailable.trade.enabled);

        let empty = kcc20_portfolio_asset_actions(true, false, false, false);
        assert!(!empty.wrap.enabled);
        assert_eq!(
            empty.wrap.reason.as_deref(),
            Some("no native KCC20 balance available to wrap")
        );
        assert!(!empty.unwrap.enabled);
        assert_eq!(
            empty.unwrap.reason.as_deref(),
            Some("no wrapped KCC20 balance available to unwrap")
        );
        assert!(!empty.trade.enabled);
        assert_eq!(
            empty.trade.reason.as_deref(),
            Some("no wrapped KCC20 balance or open orders available")
        );

        let funded = kcc20_portfolio_asset_actions(true, true, true, false);
        assert!(funded.wrap.enabled);
        assert!(funded.unwrap.enabled);
        assert!(funded.trade.enabled);
        assert!(funded.wrap.reason.is_none());
        assert!(funded.unwrap.reason.is_none());
        assert!(funded.trade.reason.is_none());

        let order_only = kcc20_portfolio_asset_actions(true, false, false, true);
        assert!(!order_only.wrap.enabled);
        assert!(!order_only.unwrap.enabled);
        assert!(order_only.trade.enabled);
        assert!(order_only.trade.reason.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn projection_freshness_reports_owner_orders_pending(pool: PgPool) {
        sqlx::query(
            r#"
            INSERT INTO kcc20_projection_dirty(reason, created_at_ms)
            VALUES ('test-owner-orders-dirty', 1000)
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let dirty_target: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
                .fetch_one(&pool)
                .await
                .unwrap();
        for projection in [
            kcc20_market_projection_name(),
            kcc20_token_page_projection_name(),
            kcc20_activity_feed_projection_name(),
            kcc20_owner_portfolio_assets_projection_name(),
        ] {
            mark_kcc20_projection_refreshed_for(&pool, projection, dirty_target)
                .await
                .unwrap();
        }

        let freshness = kcc20_projection_freshness(&pool).await.unwrap();
        assert!(freshness.owner_orders.pending);
        assert_eq!(freshness.owner_orders.last_dirty_id, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn dirty_prune_waits_for_owner_orders_projection(pool: PgPool) {
        sqlx::query(
            r#"
            INSERT INTO kcc20_projection_dirty(reason, created_at_ms)
            VALUES ('test-owner-orders-prune', 1000)
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let dirty_target: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
                .fetch_one(&pool)
                .await
                .unwrap();
        for projection in [
            kcc20_market_projection_name(),
            kcc20_token_page_projection_name(),
            kcc20_activity_feed_projection_name(),
            kcc20_owner_portfolio_assets_projection_name(),
            "owner_action_history",
        ] {
            mark_kcc20_projection_refreshed_for(&pool, projection, dirty_target)
                .await
                .unwrap();
        }

        assert_eq!(prune_kcc20_projection_dirty(&pool, 100).await.unwrap(), 0);

        mark_kcc20_projection_refreshed_for(
            &pool,
            kcc20_owner_orders_projection_name(),
            dirty_target,
        )
        .await
        .unwrap();

        assert!(prune_kcc20_projection_dirty(&pool, 100).await.unwrap() > 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn owner_orders_use_projection_after_initialized(pool: PgPool) {
        let owner = "21".repeat(32);
        let token_id = "31".repeat(32);
        sqlx::query(
            r#"
            INSERT INTO kcc20_projection_dirty(reason, created_at_ms)
            VALUES ('owner_orders_projection_added', 1000)
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let dirty_target: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
                .fetch_one(&pool)
                .await
                .unwrap();
        mark_kcc20_projection_refreshed_for(
            &pool,
            kcc20_owner_orders_projection_name(),
            dirty_target,
        )
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO kcc20_owner_orders (
                order_id, side, status, token_id, owner, token_amount,
                remaining_token_amount, price_sompi, unit_price_sompi, min_fill_amount,
                template_name, address, txid, vout, close_txid, close_entrypoint,
                created_at_ms, refreshed_at_ms
            ) VALUES (
                'order-1', 'ask', 'open', $1, $2, '10',
                '10', '1000', NULL, NULL,
                'KCC20Sale', 'kaspatest:qptest', NULL, NULL, NULL, NULL,
                5000, 6000
            )
            "#,
        )
        .bind(hex::decode(&token_id).unwrap())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();

        let rows = kcc20_owner_orders(
            &pool,
            &owner,
            Some(&token_id),
            Some("open"),
            10,
            0,
            Some(0),
            Some(1),
        )
        .await
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].order_id, "order-1");
        assert_eq!(rows[0].token_id_hex, token_id);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn owner_orders_projection_refresh_runs_on_empty_db(pool: PgPool) {
        refresh_kcc20_owner_orders(&pool).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_owner_orders")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }
}

/// All active UTXOs the indexer has seen, newest covenant first. Used to
/// render an "active covenants by value" view.
pub async fn list_active_utxos(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<CovenantUtxoRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex')  AS covenant_id_hex,
            CASE
              WHEN length(u.script_pubkey) = 35
               AND get_byte(u.script_pubkey, 0) = 170
               AND get_byte(u.script_pubkey, 1) = 32
               AND get_byte(u.script_pubkey, 34) = 135
              THEN encode(substring(u.script_pubkey FROM 3 FOR 32), 'hex')
              ELSE encode(c.script_hash, 'hex')
            END                             AS script_hash_hex,
            u.address                       AS address,
            encode(u.txid, 'hex')           AS txid_hex,
            u.vout                          AS vout,
            u.amount_sompi                  AS amount_sompi,
            u.state                         AS state,
            u.status                        AS status,
            encode(u.spent_by_txid, 'hex')  AS spent_by_txid_hex
        FROM covenant_utxos u
        JOIN covenants c ON c.covenant_id = u.covenant_id
        WHERE u.status = 'active'
        ORDER BY c.created_at_ms DESC, u.amount_sompi DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| CovenantUtxoRow {
            covenant_id_hex: r.get("covenant_id_hex"),
            script_hash_hex: r.get("script_hash_hex"),
            address: r.get("address"),
            txid_hex: r.get("txid_hex"),
            vout: r.get("vout"),
            amount_sompi: r.get("amount_sompi"),
            amount_sompi_exact: r.get::<i64, _>("amount_sompi").to_string(),
            state: r.get("state"),
            status: r.get("status"),
            spent_by_txid_hex: r.get("spent_by_txid_hex"),
        })
        .collect())
}

pub async fn covenant_active_utxos(
    pool: &PgPool,
    covenant_id_hex: &str,
    limit: i64,
    offset: i64,
    address: Option<&str>,
    owner_identifier: Option<&str>,
    state_mode: Option<i64>,
    state_null: bool,
) -> Result<Vec<CovenantUtxoRow>> {
    let raw = hex::decode(covenant_id_hex)?;
    let Some(covenant_id) = resolve_covenant_id(pool, &raw).await? else {
        return Ok(Vec::new());
    };
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex')  AS covenant_id_hex,
            CASE
              WHEN length(u.script_pubkey) = 35
               AND get_byte(u.script_pubkey, 0) = 170
               AND get_byte(u.script_pubkey, 1) = 32
               AND get_byte(u.script_pubkey, 34) = 135
              THEN encode(substring(u.script_pubkey FROM 3 FOR 32), 'hex')
              ELSE encode(c.script_hash, 'hex')
            END                             AS script_hash_hex,
            u.address                       AS address,
            encode(u.txid, 'hex')           AS txid_hex,
            u.vout                          AS vout,
            u.amount_sompi                  AS amount_sompi,
            u.state                         AS state,
            u.status                        AS status,
            encode(u.spent_by_txid, 'hex')  AS spent_by_txid_hex
        FROM covenant_utxos u
        JOIN covenants c ON c.covenant_id = u.covenant_id
        WHERE u.covenant_id = $1
          AND u.status = 'active'
          AND ($4::TEXT IS NULL OR u.address = $4)
          AND (
              $5::TEXT IS NULL
              OR lower(COALESCE(
                  u.state->>'ownerIdentifier',
                  u.state->>'owner',
                  u.state->>'stateOwner',
                  u.state->>'holderOwner',
                  ''
              )) = lower($5)
          )
          AND (
              $6::BIGINT IS NULL
              OR CASE
                  WHEN COALESCE(u.state->>'mode', u.state->>'stateMode', '') ~ '^[0-9]+$'
                  THEN COALESCE(u.state->>'mode', u.state->>'stateMode')::BIGINT
              END = $6
          )
          AND (NOT $7::BOOLEAN OR u.state IS NULL)
        ORDER BY u.amount_sompi DESC, u.txid ASC, u.vout ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(covenant_id)
    .bind(limit)
    .bind(offset)
    .bind(address)
    .bind(owner_identifier)
    .bind(state_mode)
    .bind(state_null)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(rows
        .into_iter()
        .map(|r| CovenantUtxoRow {
            covenant_id_hex: r.get("covenant_id_hex"),
            script_hash_hex: r.get("script_hash_hex"),
            address: r.get("address"),
            txid_hex: r.get("txid_hex"),
            vout: r.get("vout"),
            amount_sompi: r.get("amount_sompi"),
            amount_sompi_exact: r.get::<i64, _>("amount_sompi").to_string(),
            state: r.get("state"),
            status: r.get("status"),
            spent_by_txid_hex: r.get("spent_by_txid_hex"),
        })
        .collect())
}

pub async fn covenant_active_utxos_count(
    pool: &PgPool,
    covenant_id_hex: &str,
    address: Option<&str>,
    owner_identifier: Option<&str>,
    state_mode: Option<i64>,
    state_null: bool,
) -> Result<i64> {
    let raw = hex::decode(covenant_id_hex)?;
    let Some(covenant_id) = resolve_covenant_id(pool, &raw).await? else {
        return Ok(0);
    };
    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let count = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM covenant_utxos u
        WHERE u.covenant_id = $1
          AND u.status = 'active'
          AND ($2::TEXT IS NULL OR u.address = $2)
          AND (
              $3::TEXT IS NULL
              OR lower(COALESCE(
                  u.state->>'ownerIdentifier',
                  u.state->>'owner',
                  u.state->>'stateOwner',
                  u.state->>'holderOwner',
                  ''
              )) = lower($3)
          )
          AND (
              $4::BIGINT IS NULL
              OR CASE
                  WHEN COALESCE(u.state->>'mode', u.state->>'stateMode', '') ~ '^[0-9]+$'
                  THEN COALESCE(u.state->>'mode', u.state->>'stateMode')::BIGINT
              END = $4
          )
          AND (NOT $5::BOOLEAN OR u.state IS NULL)
        "#,
    )
    .bind(covenant_id)
    .bind(address)
    .bind(owner_identifier)
    .bind(state_mode)
    .bind(state_null)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count)
}

pub async fn active_utxos_by_address(
    pool: &PgPool,
    address: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<CovenantUtxoRow>> {
    let rows = sqlx::query(ACTIVE_UTXOS_BY_ADDRESS_SQL)
        .bind(address)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(covenant_utxo_row_from_sql).collect())
}

pub async fn active_utxos_by_address_page(
    pool: &PgPool,
    address: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<CovenantUtxoRow>, i64)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        COVENANT_LIST_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = sqlx::query(ACTIVE_UTXOS_BY_ADDRESS_SQL)
        .bind(address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
    let total = active_utxos_by_address_count_tx(&mut tx, address).await?;
    tx.commit().await?;

    Ok((
        rows.into_iter().map(covenant_utxo_row_from_sql).collect(),
        total,
    ))
}

const ACTIVE_UTXOS_BY_ADDRESS_SQL: &str = r#"
        SELECT
            encode(c.covenant_id, 'hex')  AS covenant_id_hex,
            CASE
              WHEN length(u.script_pubkey) = 35
               AND get_byte(u.script_pubkey, 0) = 170
               AND get_byte(u.script_pubkey, 1) = 32
               AND get_byte(u.script_pubkey, 34) = 135
              THEN encode(substring(u.script_pubkey FROM 3 FOR 32), 'hex')
              ELSE encode(c.script_hash, 'hex')
            END                             AS script_hash_hex,
            u.address                       AS address,
            encode(u.txid, 'hex')           AS txid_hex,
            u.vout                          AS vout,
            u.amount_sompi                  AS amount_sompi,
            u.state                         AS state,
            u.status                        AS status,
            encode(u.spent_by_txid, 'hex')  AS spent_by_txid_hex
        FROM covenant_utxos u
        JOIN covenants c ON c.covenant_id = u.covenant_id
        WHERE u.address = $1
          AND u.status = 'active'
        ORDER BY u.amount_sompi DESC, u.txid ASC, u.vout ASC
        LIMIT $2 OFFSET $3
        "#;

fn covenant_utxo_row_from_sql(r: PgRow) -> CovenantUtxoRow {
    CovenantUtxoRow {
        covenant_id_hex: r.get("covenant_id_hex"),
        script_hash_hex: r.get("script_hash_hex"),
        address: r.get("address"),
        txid_hex: r.get("txid_hex"),
        vout: r.get("vout"),
        amount_sompi: r.get("amount_sompi"),
        amount_sompi_exact: r.get::<i64, _>("amount_sompi").to_string(),
        state: r.get("state"),
        status: r.get("status"),
        spent_by_txid_hex: r.get("spent_by_txid_hex"),
    }
}

async fn active_utxos_by_address_count_tx(
    tx: &mut Transaction<'_, Postgres>,
    address: &str,
) -> Result<i64> {
    let total = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM covenant_utxos WHERE address = $1 AND status = 'active'",
    )
    .bind(address)
    .fetch_one(&mut **tx)
    .await?;
    Ok(total)
}

pub async fn active_utxos_by_address_count(pool: &PgPool, address: &str) -> Result<i64> {
    let total = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM covenant_utxos WHERE address = $1 AND status = 'active'",
    )
    .bind(address)
    .fetch_one(pool)
    .await?;
    Ok(total)
}

pub async fn fomo_rounds(
    pool: &PgPool,
    active_only: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<FomoRoundRow>> {
    let sql = fomo_rounds_query(
        r#"
        WHERE COALESCE(c.template_name, c.claimed_template) = 'KaspaFomoRound'
          AND ($1::BOOL = FALSE OR active_utxo.txid IS NOT NULL)
        ORDER BY COALESCE(action_totals.last_action_time_ms, c.created_at_ms) DESC, c.created_at_ms DESC
        LIMIT $2 OFFSET $3
        "#,
    );
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(active_only)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(fomo_round_row_from_sql).collect())
}

pub async fn fomo_rounds_count(pool: &PgPool, active_only: bool) -> Result<i64> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*)::BIGINT AS total
        FROM covenants c
        WHERE COALESCE(c.template_name, c.claimed_template) = 'KaspaFomoRound'
          AND (
              $1::BOOL = FALSE
              OR EXISTS (
                  SELECT 1
                  FROM covenant_utxos u
                  WHERE u.covenant_id = c.covenant_id
                    AND u.status = 'active'
              )
          )
        "#,
    )
    .bind(active_only)
    .fetch_one(pool)
    .await?;

    Ok(row.get("total"))
}

pub async fn fomo_round_by_id(
    pool: &PgPool,
    covenant_id_hex: &str,
) -> Result<Option<FomoRoundRow>> {
    let covenant_id = hex::decode(covenant_id_hex)?;
    let sql = fomo_rounds_query(
        r#"
        WHERE (c.covenant_id = $1 OR c.script_hash = $1)
          AND COALESCE(c.template_name, c.claimed_template) = 'KaspaFomoRound'
        LIMIT 1
        "#,
    );
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(covenant_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(fomo_round_row_from_sql))
}

fn fomo_rounds_query(where_and_order: &str) -> String {
    format!(
        r#"
        SELECT
            encode(c.covenant_id, 'hex') AS covenant_id_hex,
            encode(c.script_hash, 'hex')  AS script_hash_hex,
            c.address                      AS address,
            CASE
              WHEN active_utxo.txid IS NOT NULL THEN 'active'
              WHEN settle.txid IS NOT NULL THEN 'settled'
              ELSE 'spent'
            END                            AS status,
            active_utxo.amount_sompi::TEXT AS pot_sompi,
            encode(active_utxo.txid, 'hex') AS active_txid_hex,
            active_utxo.vout               AS active_vout,
            COALESCE(active_utxo.state, c.constructor_args) AS state,
            COALESCE(active_utxo.state, c.constructor_args)->>'lastBuyer' AS last_buyer,
            COALESCE(active_utxo.state, c.constructor_args)->>'endTimeMs' AS end_time_ms,
            COALESCE(active_utxo.state, c.constructor_args)->>'ticketCount' AS ticket_count,
            COALESCE(action_totals.buy_count, 0)::BIGINT AS buy_count,
            encode(settle.txid, 'hex') AS settled_txid_hex,
            c.created_at_ms,
            action_totals.last_action_time_ms
        FROM covenants c
        LEFT JOIN LATERAL (
            SELECT u.txid, u.vout, u.amount_sompi, u.state
            FROM covenant_utxos u
            WHERE u.covenant_id = c.covenant_id
              AND u.status = 'active'
            ORDER BY u.created_block DESC, u.txid DESC, u.vout ASC
            LIMIT 1
        ) active_utxo ON TRUE
        LEFT JOIN LATERAL (
            SELECT a.txid
            FROM covenant_actions a
            WHERE a.covenant_id = c.covenant_id
              AND a.action = 'spend'
              AND a.entrypoint = 'settle'
            ORDER BY a.block_time_ms DESC, a.id DESC
            LIMIT 1
        ) settle ON TRUE
        LEFT JOIN LATERAL (
            SELECT
                COUNT(*) FILTER (WHERE a.action = 'spend' AND a.entrypoint = 'buy')::BIGINT AS buy_count,
                MAX(a.block_time_ms) AS last_action_time_ms
            FROM covenant_actions a
            WHERE a.covenant_id = c.covenant_id
        ) action_totals ON TRUE
        {where_and_order}
        "#
    )
}

fn fomo_round_row_from_sql(r: sqlx::postgres::PgRow) -> FomoRoundRow {
    FomoRoundRow {
        covenant_id_hex: r.get("covenant_id_hex"),
        script_hash_hex: r.get("script_hash_hex"),
        address: r.get("address"),
        status: r.get("status"),
        pot_sompi: r.get("pot_sompi"),
        active_txid_hex: r.get("active_txid_hex"),
        active_vout: r.get("active_vout"),
        state: r.get("state"),
        last_buyer: r.get("last_buyer"),
        end_time_ms: r.get("end_time_ms"),
        ticket_count: r.get("ticket_count"),
        buy_count: r.get("buy_count"),
        settled_txid_hex: r.get("settled_txid_hex"),
        created_at_ms: r.get("created_at_ms"),
        last_action_time_ms: r.get("last_action_time_ms"),
    }
}

pub async fn covenant_template_summaries(pool: &PgPool) -> Result<Vec<CovenantTemplateSummaryRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            template,
            covenant_count,
            verified_count,
            claimed_only_count,
            active_covenants,
            active_utxos,
            total_amount_sompi::text AS total_amount_sompi,
            action_count,
            matched_count,
            unrevealed_count,
            unmatched_count,
            latest_created_at_ms,
            latest_action_time_ms
        FROM covenant_template_summaries
        ORDER BY covenant_count DESC, template ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| CovenantTemplateSummaryRow {
            template: r.get("template"),
            covenant_count: r.get("covenant_count"),
            verified_count: r.get("verified_count"),
            claimed_only_count: r.get("claimed_only_count"),
            active_covenants: r.get("active_covenants"),
            active_utxos: r.get("active_utxos"),
            total_amount_sompi: r.get("total_amount_sompi"),
            action_count: r.get("action_count"),
            matched_count: r.get("matched_count"),
            unrevealed_count: r.get("unrevealed_count"),
            unmatched_count: r.get("unmatched_count"),
            latest_created_at_ms: r.get("latest_created_at_ms"),
            latest_action_time_ms: r.get("latest_action_time_ms"),
        })
        .collect())
}

pub async fn explorer_search(
    pool: &PgPool,
    q: &str,
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    explorer_search_with_aliases(pool, q, &[], limit).await
}

pub async fn explorer_search_with_aliases(
    pool: &PgPool,
    q: &str,
    aliases: &[String],
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    let q = q.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }

    let limit = limit.clamp(1, 50);
    let alias_values = normalized_filter_values(Some(q), aliases);
    let mut results = if q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit()) {
        let hex_id = hex::decode(q)?;
        explorer_search_hex(pool, &hex_id, limit).await?
    } else if q.starts_with("kaspa") {
        explorer_search_address(pool, q, limit).await?
    } else {
        explorer_search_text(pool, q, limit).await?
    };
    if !alias_values.is_empty() {
        results.extend(explorer_search_identity_values(pool, &alias_values, limit).await?);
    }
    Ok(dedupe_search_results(results, limit))
}

fn dedupe_search_results(
    results: Vec<ExplorerSearchResult>,
    limit: i64,
) -> Vec<ExplorerSearchResult> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for result in results {
        let key = (result.kind.clone(), result.id.clone(), result.path.clone());
        if seen.insert(key) {
            deduped.push(result);
        }
    }
    deduped.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.label.cmp(&b.label))
    });
    deduped.truncate(limit as usize);
    deduped
}

async fn explorer_search_hex(
    pool: &PgPool,
    hex_id: &[u8],
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    let rows = sqlx::query(
        r#"
        WITH results AS (
            SELECT DISTINCT
                'covenant'::TEXT AS kind,
                COALESCE(c.template_name, c.claimed_template, 'Unrevealed covenant') AS label,
                concat_ws(
                    ' · ',
                    c.classification_kind || '/' || c.classification_status,
                    NULLIF(c.address, '')
                ) AS description,
                encode(c.covenant_id, 'hex') AS id,
                '/covenants/' || encode(c.covenant_id, 'hex') AS path,
                c.classification_status AS status,
                CASE
                    WHEN c.covenant_id = $1 THEN 100
                    WHEN c.script_hash = $1 THEN 95
                    WHEN c.genesis_txid = $1 THEN 90
                    ELSE 45
                END::INT AS score
            FROM covenants c
            WHERE c.covenant_id = $1 OR c.script_hash = $1 OR c.genesis_txid = $1

            UNION ALL

            SELECT DISTINCT
                'transaction'::TEXT AS kind,
                a.action || COALESCE(' / ' || a.entrypoint, '') AS label,
                concat_ws(
                    ' · ',
                    COALESCE(c.template_name, c.claimed_template, 'Unrevealed covenant'),
                    c.classification_kind || '/' || c.classification_status
                ) AS description,
                encode(a.txid, 'hex') AS id,
                '/tx/' || encode(a.txid, 'hex') AS path,
                c.classification_status AS status,
                88::INT AS score
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE a.txid = $1

            UNION ALL

            SELECT
                'kcc20'::TEXT AS kind,
                'KCC20 token summary'::TEXT AS label,
                concat_ws(
                    ' · ',
                    'wrapper ' || encode(s.wrapper_id, 'hex'),
                    'holders ' || s.holder_count::TEXT,
                    'orderbook ' || s.orderbook_tradeable_supply::TEXT
                ) AS description,
                encode(s.token_id, 'hex') AS id,
                '/kcc20/' || encode(s.token_id, 'hex') AS path,
                NULL::TEXT AS status,
                82::INT AS score
            FROM kcc20_token_summaries s
            WHERE s.token_id = $1 OR s.wrapper_id = $1
        )
        SELECT kind, label, description, id, path, status, score
        FROM results
        ORDER BY score DESC, kind ASC, label ASC
        LIMIT $2
        "#,
    )
    .bind(hex_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(explorer_search_results_from_rows(rows))
}

async fn explorer_search_address(
    pool: &PgPool,
    address: &str,
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    let rows = sqlx::query(
        r#"
        WITH results AS (
            SELECT DISTINCT
                'covenant'::TEXT AS kind,
                COALESCE(c.template_name, c.claimed_template, 'Unrevealed covenant') AS label,
                c.classification_kind || '/' || c.classification_status AS description,
                encode(c.covenant_id, 'hex') AS id,
                '/covenants/' || encode(c.covenant_id, 'hex') AS path,
                c.classification_status AS status,
                80::INT AS score
            FROM covenants c
            WHERE c.address = $1

            UNION ALL

            SELECT DISTINCT
                'address'::TEXT AS kind,
                u.address AS label,
                COUNT(*)::TEXT || ' covenant UTXO rows' AS description,
                u.address AS id,
                '/addresses/' || u.address AS path,
                NULL::TEXT AS status,
                70::INT AS score
            FROM covenant_utxos u
            WHERE u.address = $1
            GROUP BY u.address
        )
        SELECT kind, label, description, id, path, status, score
        FROM results
        ORDER BY score DESC, kind ASC, label ASC
        LIMIT $2
        "#,
    )
    .bind(address)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(explorer_search_results_from_rows(rows))
}

async fn explorer_search_identity_values(
    pool: &PgPool,
    values: &[String],
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    let rows = sqlx::query(
        r#"
        WITH identity_values(value, value_hash) AS (
            SELECT value, md5(value)
            FROM unnest($1::TEXT[]) AS value
        ),
        matches AS (
            SELECT DISTINCT
                'covenant'::TEXT AS kind,
                COALESCE(c.template_name, c.claimed_template, 'Unrevealed covenant') AS label,
                concat_ws(
                    ' · ',
                    c.classification_kind || '/' || c.classification_status,
                    COALESCE(s.current_address, c.address),
                    participant_roles.roles
                ) AS description,
                encode(c.covenant_id, 'hex') AS id,
                '/covenants/' || encode(c.covenant_id, 'hex') AS path,
                c.classification_status AS status,
                c.created_at_ms
            FROM covenants c
            LEFT JOIN covenant_summaries s ON s.covenant_id = c.covenant_id
            LEFT JOIN LATERAL (
                SELECT string_agg(
                    DISTINCT
                    CASE
                        WHEN p.source = 'claimed_args' AND c.claim_verified THEN 'claimed/verified ' || p.name
                        WHEN p.source = 'claimed_args' THEN 'claimed/unverified ' || p.name
                        ELSE p.source || ' ' || p.name
                    END,
                    ', '
                ) AS roles
                FROM covenant_participants p
                JOIN identity_values iv
                  ON iv.value_hash = p.value_hash
                 AND iv.value = p.value_normalized
                WHERE p.covenant_id = c.covenant_id
            ) participant_roles ON TRUE
            WHERE c.address = ANY($1::TEXT[])
               OR s.current_address = ANY($1::TEXT[])
               OR EXISTS (
                   SELECT 1
                   FROM covenant_participants p
                   JOIN identity_values iv
                     ON iv.value_hash = p.value_hash
                    AND iv.value = p.value_normalized
                   WHERE p.covenant_id = c.covenant_id
               )
        ),
        ranked AS (
            SELECT
                *,
                ROW_NUMBER() OVER (ORDER BY created_at_ms DESC, label ASC, id ASC) AS recency_rank
            FROM matches
        )
        SELECT
            kind,
            label,
            description,
            id,
            path,
            status,
            (95 - LEAST(recency_rank::INT, 30))::INT AS score
        FROM ranked
        ORDER BY recency_rank ASC
        LIMIT $2
        "#,
    )
    .bind(values)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(explorer_search_results_from_rows(rows))
}

async fn explorer_search_text(
    pool: &PgPool,
    q: &str,
    limit: i64,
) -> Result<Vec<ExplorerSearchResult>> {
    let pattern = format!("%{}%", q);
    let rows = sqlx::query(
        r#"
        SELECT
            'template'::TEXT AS kind,
            template AS label,
            concat_ws(
                ' · ',
                covenant_count::TEXT || ' covenants',
                action_count::TEXT || ' actions',
                active_utxos::TEXT || ' active UTXOs'
            ) AS description,
            template AS id,
            '/covenants?template=' || template AS path,
            NULL::TEXT AS status,
            45::INT AS score
        FROM covenant_template_summaries
        WHERE template ILIKE $1
        ORDER BY action_count DESC, template ASC
        LIMIT $2
        "#,
    )
    .bind(pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(explorer_search_results_from_rows(rows))
}

fn explorer_search_results_from_rows(rows: Vec<PgRow>) -> Vec<ExplorerSearchResult> {
    rows.into_iter()
        .map(|r| ExplorerSearchResult {
            kind: r.get("kind"),
            label: r.get("label"),
            description: r.get("description"),
            id: r.get("id"),
            path: r.get("path"),
            status: r.get("status"),
            score: r.get("score"),
        })
        .collect()
}

pub async fn kcc20_holders(
    pool: &PgPool,
    covenant_id_hex: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20HolderRow>> {
    let covenant_id = hex::decode(covenant_id_hex)?;
    let rows = sqlx::query(
        r#"
        SELECT
            encode(covenant_id, 'hex')      AS covenant_id_hex,
            encode(owner_identifier, 'hex') AS owner_identifier,
            identifier_type                 AS identifier_type,
            amount_total::TEXT              AS amount,
            utxo_count                      AS utxo_count,
            is_minter                       AS is_minter,
            last_change_ms                  AS last_change_ms
        FROM kcc20_holders
        WHERE covenant_id = $1
          AND is_minter = FALSE
        ORDER BY amount_total DESC, owner_identifier ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(covenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let identifier_type = r.get::<i16, _>("identifier_type");
            Kcc20HolderRow {
                covenant_id_hex: r.get("covenant_id_hex"),
                owner_identifier: r.get("owner_identifier"),
                identifier_type,
                identifier_type_name: kcc20_identifier_type_name(identifier_type).to_string(),
                amount: r.get("amount"),
                utxo_count: r.get("utxo_count"),
                is_minter: r.get("is_minter"),
                last_change_ms: r.get("last_change_ms"),
            }
        })
        .collect())
}

pub async fn kcc20_holders_count(pool: &PgPool, covenant_id_hex: &str) -> Result<i64> {
    let covenant_id = hex::decode(covenant_id_hex)?;
    let count = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM kcc20_holders WHERE covenant_id = $1 AND is_minter = FALSE",
    )
    .bind(covenant_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn kcc20_active_utxos(
    pool: &PgPool,
    covenant_id_hex: &str,
    limit: i64,
    offset: i64,
    address: Option<&str>,
    owner_identifier: Option<&str>,
    state_mode: Option<i64>,
    state_null: bool,
) -> Result<Vec<CovenantUtxoRow>> {
    covenant_active_utxos(
        pool,
        covenant_id_hex,
        limit,
        offset,
        address,
        owner_identifier,
        state_mode,
        state_null,
    )
    .await
}

pub async fn kcc20_listings(
    pool: &PgPool,
    token_id_hex: Option<&str>,
    seller: Option<&str>,
) -> Result<Vec<Kcc20ListingRow>> {
    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let mut tx = pool.begin().await?;
    set_local_kcc20_orderbook_limits(&mut tx).await?;
    let rows = sqlx::query(
        include_str!("repo/kcc20_listings.sql"),
    )
    .bind(token_id)
    .bind(seller)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    if rows.len() > KCC20_ORDERBOOK_MAX_ROWS {
        anyhow::bail!(
            "KCC20 listing query exceeds the safe {} row limit",
            KCC20_ORDERBOOK_MAX_ROWS
        );
    }

    Ok(rows
        .into_iter()
        .map(|r| Kcc20ListingRow {
            order_id: r.get("order_id"),
            txid_hex: r.get("txid_hex"),
            vout: r.get("vout"),
            template_name: r.get("template_name"),
            market_side: r.get("market_side"),
            sale_covenant_id_hex: r.get("sale_covenant_id_hex"),
            sale_script_hash_hex: r.get("sale_script_hash_hex"),
            sale_address: r.get("sale_address"),
            token_id_hex: r
                .get::<Option<String>, _>("token_id_hex")
                .unwrap_or_default(),
            seller: r.get("seller"),
            token_amount: r.get("token_amount"),
            price_sompi: r.get("price_sompi"),
            unit_price_sompi: r.get("unit_price_sompi"),
            min_fill_amount: r.get("min_fill_amount"),
            fee_ticket_id: r.get("fee_ticket_id"),
            status: r.get("status"),
            close_txid_hex: r.get("close_txid_hex"),
            close_entrypoint: r.get("close_entrypoint"),
            sale_utxos: r.get("sale_utxos"),
            locked_token_utxos: r.get("locked_token_utxos"),
            locked_token_amount: r.get("locked_token_amount"),
            created_at_ms: r.get("created_at_ms"),
        })
        .collect())
}

pub async fn kcc20_bids(
    pool: &PgPool,
    token_id_hex: Option<&str>,
    buyer: Option<&str>,
) -> Result<Vec<Kcc20BidRow>> {
    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let mut tx = pool.begin().await?;
    set_local_kcc20_orderbook_limits(&mut tx).await?;
    let rows = sqlx::query(
        include_str!("repo/kcc20_bids.sql"),
    )
    .bind(token_id)
    .bind(buyer)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    if rows.len() > KCC20_ORDERBOOK_MAX_ROWS {
        anyhow::bail!(
            "KCC20 bid query exceeds the safe {} row limit",
            KCC20_ORDERBOOK_MAX_ROWS
        );
    }

    Ok(rows
        .into_iter()
        .map(|r| Kcc20BidRow {
            order_id: r.get("order_id"),
            txid_hex: r.get("txid_hex"),
            vout: r.get("vout"),
            template_name: r.get("template_name"),
            market_side: r.get("market_side"),
            bid_covenant_id_hex: r.get("bid_covenant_id_hex"),
            bid_script_hash_hex: r.get("bid_script_hash_hex"),
            bid_address: r.get("bid_address"),
            token_id_hex: r
                .get::<Option<String>, _>("token_id_hex")
                .unwrap_or_default(),
            buyer: r.get("buyer"),
            token_amount: r.get("token_amount"),
            price_sompi: r.get("price_sompi"),
            unit_price_sompi: r.get("unit_price_sompi"),
            min_fill_amount: r.get("min_fill_amount"),
            fee_ticket_id: r.get("fee_ticket_id"),
            status: r.get("status"),
            close_txid_hex: r.get("close_txid_hex"),
            close_entrypoint: r.get("close_entrypoint"),
            bid_utxos: r.get("bid_utxos"),
            bid_value_sompi: r.get("bid_value_sompi"),
            created_at_ms: r.get("created_at_ms"),
        })
        .collect())
}

pub async fn kcc20_owner_orders(
    pool: &PgPool,
    owner: &str,
    token_id_hex: Option<&str>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<Kcc20OwnerOrderRow>> {
    if kcc20_owner_orders_initialized(pool).await? {
        return kcc20_owner_orders_projected(
            pool,
            owner,
            token_id_hex,
            status,
            limit,
            offset,
            from_ms,
            to_ms,
        )
        .await;
    }

    if status == Some("open") {
        return kcc20_open_owner_orders(pool, owner, token_id_hex, limit, offset).await;
    }

    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let rows = sqlx::query(
        r#"
        WITH RECURSIVE sale_raw AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND claim_verified = TRUE
              AND (
                  COALESCE(constructor_args->>'seller', constructor_args->>'listingSeller') = $2
                  OR EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements(
                          CASE
                              WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                              ELSE '[]'::jsonb
                          END
                      ) AS arg
                      WHERE arg->>'name' IN ('seller', 'listingSeller')
                        AND arg->>'value' = $2
                  )
              )
        ),
        sale AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM sale_raw
        ),
        owner_sale AS (
            SELECT *
            FROM sale
            WHERE COALESCE(args->>'seller', args->>'listingSeller') = $2
              AND COALESCE(args->>'tokenId', args->>'listingTokenId') ~ '^[0-9a-fA-F]{64}$'
              AND ($1::BYTEA IS NULL OR decode(COALESCE(args->>'tokenId', args->>'listingTokenId'), 'hex') = $1)
        ),
        sale_family(root_covenant_id, covenant_id) AS (
            SELECT covenant_id, covenant_id
            FROM owner_sale
            UNION
            SELECT sf.root_covenant_id, child.covenant_id
            FROM sale_family sf
            JOIN covenant_actions parent_spend
              ON parent_spend.covenant_id = sf.covenant_id
             AND parent_spend.action = 'spend'
            JOIN covenants child
              ON child.genesis_txid = parent_spend.txid
            WHERE COALESCE(child.template_name, child.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND child.claim_verified = TRUE
        ),
        sale_spend AS (
            SELECT DISTINCT ON (sf.root_covenant_id)
                sf.root_covenant_id AS covenant_id,
                a.entrypoint,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms
            FROM sale_family sf
            JOIN covenant_actions a
              ON a.covenant_id = sf.covenant_id
             AND a.action = 'spend'
            ORDER BY sf.root_covenant_id, a.block_time_ms DESC, a.id DESC
        ),
        legacy_asks AS (
            SELECT
                encode(s.covenant_id, 'hex') AS order_id,
                'ask'::TEXT                  AS side,
                CASE
                    WHEN ss.entrypoint IN ('buy', 'buyListing') THEN 'filled'
                    WHEN ss.entrypoint IN ('cancel', 'cancelListing') THEN 'cancelled'
                    WHEN COUNT(DISTINCT su.txid) FILTER (WHERE su.status = 'active') > 0
                     AND COUNT(DISTINCT tu.txid) FILTER (WHERE tu.status = 'active') > 0 THEN 'open'
                    WHEN COUNT(DISTINCT su.txid) FILTER (WHERE su.status = 'active') > 0 THEN 'waitingForLock'
                    ELSE 'closed'
                END                           AS status,
                COALESCE(s.args->>'tokenId', s.args->>'listingTokenId') AS token_id_hex,
                COALESCE(s.args->>'seller', s.args->>'listingSeller')    AS owner,
                COALESCE(s.args->>'tokenAmount', s.args->>'listingTokenAmount') AS token_amount,
                SUM((COALESCE(tu.state->>'stateAmount', tu.state->>'amount'))::NUMERIC) FILTER (WHERE tu.status = 'active')::TEXT
                                                AS remaining_token_amount,
                COALESCE(s.args->>'priceSompi', s.args->>'listingPriceSompi') AS price_sompi,
                NULL::TEXT                     AS unit_price_sompi,
                NULL::TEXT                     AS min_fill_amount,
                s.template_name                AS template_name,
                s.address                      AS address,
                NULL::TEXT                     AS txid_hex,
                NULL::INT                      AS vout,
                ss.txid_hex                    AS close_txid_hex,
                ss.entrypoint                  AS close_entrypoint,
                s.created_at_ms                AS created_at_ms
            FROM owner_sale s
            LEFT JOIN sale_spend ss
                   ON ss.covenant_id = s.covenant_id
            LEFT JOIN sale_family suf
                   ON suf.root_covenant_id = s.covenant_id
            LEFT JOIN covenant_utxos su
                   ON su.covenant_id = suf.covenant_id
            LEFT JOIN covenant_utxos tu
                   ON tu.covenant_id = decode(COALESCE(s.args->>'tokenId', s.args->>'listingTokenId'), 'hex')
                  AND tu.status = 'active'
                  AND COALESCE(tu.state->>'stateOwner', tu.state->>'ownerIdentifier') = encode(s.covenant_id, 'hex')
                  AND (COALESCE(tu.state->>'stateOwnerType', tu.state->>'identifierType'))::INT = 2
            GROUP BY s.covenant_id, s.address, s.template_name, s.args, s.created_at_ms,
                     ss.txid_hex, ss.entrypoint
        ),
        orderbook_asks AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'ask'::TEXT                                  AS side,
                'open'::TEXT                                 AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                               AS token_id_hex,
                u.state->>'ownerIdentifier'                  AS owner,
                u.state->>'amount'                           AS token_amount,
                u.state->>'amount'                           AS remaining_token_amount,
                ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                                                               AS price_sompi,
                u.state->>'unitPriceSompi'                   AS unit_price_sompi,
                u.state->>'minFillAmount'                    AS min_fill_amount,
                CASE
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END                                           AS template_name,
                u.address                                    AS address,
                encode(u.txid, 'hex')                        AS txid_hex,
                u.vout                                       AS vout,
                NULL::TEXT                                   AS close_txid_hex,
                NULL::TEXT                                   AS close_entrypoint,
                b.timestamp_ms                               AS created_at_ms
            FROM covenant_utxos u
            JOIN covenants c
              ON c.covenant_id = u.covenant_id
            JOIN blocks b
              ON b.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
              )
              AND u.state ? 'ownerIdentifier'
              AND u.state ? 'mode'
              AND u.state->>'mode' = '2'
              AND u.state->>'ownerIdentifier' = $2
              AND (
                  $1::BYTEA IS NULL
                  OR u.covenant_id = $1
                  OR (
                      NULLIF(u.state->>'canonicalTokenId', '') ~ '^[0-9a-fA-F]{64}$'
                      AND decode(u.state->>'canonicalTokenId', 'hex') = $1
                  )
              )
        ),
        bid_raw AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder')
              AND claim_verified = TRUE
              AND (
                  COALESCE(constructor_args->>'buyer', constructor_args->>'orderBuyer') = $2
                  OR EXISTS (
                      SELECT 1
                      FROM jsonb_array_elements(
                          CASE
                              WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                              ELSE '[]'::jsonb
                          END
                      ) AS arg
                      WHERE arg->>'name' IN ('buyer', 'orderBuyer')
                        AND arg->>'value' = $2
                  )
              )
        ),
        bid AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM bid_raw
        ),
        owner_bid AS (
            SELECT *
            FROM bid
            WHERE COALESCE(args->>'buyer', args->>'orderBuyer') = $2
              AND COALESCE(args->>'tokenId', args->>'orderedTokenId') ~ '^[0-9a-fA-F]{64}$'
              AND ($1::BYTEA IS NULL OR decode(COALESCE(args->>'tokenId', args->>'orderedTokenId'), 'hex') = $1)
        ),
        bid_spend AS (
            SELECT DISTINCT ON (a.covenant_id)
                a.covenant_id,
                a.entrypoint,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms
            FROM covenant_actions a
            JOIN owner_bid b
              ON b.covenant_id = a.covenant_id
            WHERE a.action = 'spend'
            ORDER BY a.covenant_id, a.block_time_ms DESC, a.id DESC
        ),
        legacy_bids AS (
            SELECT
                encode(b.covenant_id, 'hex') AS order_id,
                'bid'::TEXT                  AS side,
                CASE
                    WHEN bs.entrypoint IN ('fillBuyOrder') THEN 'filled'
                    WHEN bs.entrypoint IN ('cancelBuyOrder') THEN 'cancelled'
                    WHEN COUNT(DISTINCT bu.txid) FILTER (WHERE bu.status = 'active') > 0 THEN 'open'
                    ELSE 'closed'
                END                           AS status,
                COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId') AS token_id_hex,
                COALESCE(b.args->>'buyer', b.args->>'orderBuyer') AS owner,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS token_amount,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS remaining_token_amount,
                COALESCE(b.args->>'priceSompi', b.args->>'offerPriceSompi') AS price_sompi,
                NULL::TEXT                   AS unit_price_sompi,
                NULL::TEXT                   AS min_fill_amount,
                b.template_name              AS template_name,
                b.address                    AS address,
                NULL::TEXT                   AS txid_hex,
                NULL::INT                    AS vout,
                bs.txid_hex                  AS close_txid_hex,
                bs.entrypoint                AS close_entrypoint,
                b.created_at_ms              AS created_at_ms
            FROM owner_bid b
            LEFT JOIN bid_spend bs
                   ON bs.covenant_id = b.covenant_id
            LEFT JOIN covenant_utxos bu
                   ON bu.covenant_id = b.covenant_id
            GROUP BY b.covenant_id, b.address, b.template_name, b.args, b.created_at_ms,
                     bs.txid_hex, bs.entrypoint
        ),
        orderbook_bids AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'bid'::TEXT                                  AS side,
                'open'::TEXT                                 AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                               AS token_id_hex,
                u.state->>'ownerIdentifier'                  AS owner,
                u.state->>'amount'                           AS token_amount,
                u.state->>'amount'                           AS remaining_token_amount,
                ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                                                               AS price_sompi,
                u.state->>'unitPriceSompi'                   AS unit_price_sompi,
                u.state->>'minFillAmount'                    AS min_fill_amount,
                CASE
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END                                           AS template_name,
                u.address                                    AS address,
                encode(u.txid, 'hex')                        AS txid_hex,
                u.vout                                       AS vout,
                NULL::TEXT                                   AS close_txid_hex,
                NULL::TEXT                                   AS close_entrypoint,
                blk.timestamp_ms                             AS created_at_ms
            FROM covenant_utxos u
            JOIN covenants c
              ON c.covenant_id = u.covenant_id
            JOIN blocks blk
              ON blk.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
              )
              AND u.state ? 'ownerIdentifier'
              AND u.state ? 'mode'
              AND u.state->>'mode' = '3'
              AND u.state->>'ownerIdentifier' = $2
              AND (
                  $1::BYTEA IS NULL
                  OR u.covenant_id = $1
                  OR (
                      NULLIF(u.state->>'canonicalTokenId', '') ~ '^[0-9a-fA-F]{64}$'
                      AND decode(u.state->>'canonicalTokenId', 'hex') = $1
                  )
              )
        ),
        orders AS (
            SELECT * FROM legacy_asks
            UNION ALL
            SELECT * FROM orderbook_asks
            UNION ALL
            SELECT * FROM legacy_bids
            UNION ALL
            SELECT * FROM orderbook_bids
        )
        SELECT *
        FROM orders
        WHERE ($3::TEXT IS NULL OR status = $3)
          AND ($6::BIGINT IS NULL OR created_at_ms >= $6)
          AND ($7::BIGINT IS NULL OR created_at_ms < $7)
        ORDER BY created_at_ms DESC, order_id DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(token_id)
    .bind(owner)
    .bind(status)
    .bind(limit)
    .bind(offset)
    .bind(from_ms)
    .bind(to_ms)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(kcc20_owner_order_from_row).collect())
}

async fn kcc20_owner_orders_projected(
    pool: &PgPool,
    owner: &str,
    token_id_hex: Option<&str>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<Kcc20OwnerOrderRow>> {
    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let owner = owner.to_ascii_lowercase();
    let rows = sqlx::query(
        r#"
        SELECT
            order_id,
            side,
            status,
            encode(token_id, 'hex') AS token_id_hex,
            owner,
            token_amount,
            remaining_token_amount,
            price_sompi,
            unit_price_sompi,
            min_fill_amount,
            template_name,
            address,
            encode(txid, 'hex') AS txid_hex,
            vout,
            encode(close_txid, 'hex') AS close_txid_hex,
            close_entrypoint,
            created_at_ms
        FROM kcc20_owner_orders
        WHERE owner = $1
          AND ($2::BYTEA IS NULL OR token_id = $2)
          AND ($3::TEXT IS NULL OR status = $3)
          AND ($3::TEXT = 'open' OR $4::BIGINT IS NULL OR created_at_ms >= $4)
          AND ($3::TEXT = 'open' OR $5::BIGINT IS NULL OR created_at_ms < $5)
        ORDER BY created_at_ms DESC, order_id DESC
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(owner)
    .bind(token_id)
    .bind(status)
    .bind(from_ms)
    .bind(to_ms)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(kcc20_owner_order_from_row).collect())
}

async fn kcc20_open_owner_orders(
    pool: &PgPool,
    owner: &str,
    token_id_hex: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20OwnerOrderRow>> {
    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let rows = sqlx::query(
        r#"
        WITH RECURSIVE sale_raw AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND claim_verified = TRUE
              AND COALESCE(constructor_args->>'seller', constructor_args->>'listingSeller') = $2

            UNION ALL

            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND claim_verified = TRUE
              AND (constructor_args IS NULL OR constructor_args = 'null'::jsonb)
              AND EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      CASE
                          WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                          ELSE '[]'::jsonb
                      END
                  ) AS arg
                  WHERE arg->>'name' IN ('seller', 'listingSeller')
                    AND arg->>'value' = $2
              )
        ),
        sale AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM sale_raw
        ),
        owner_sale AS (
            SELECT *
            FROM sale
            WHERE COALESCE(args->>'seller', args->>'listingSeller') = $2
              AND COALESCE(args->>'tokenId', args->>'listingTokenId') ~ '^[0-9a-fA-F]{64}$'
              AND ($1::BYTEA IS NULL OR decode(COALESCE(args->>'tokenId', args->>'listingTokenId'), 'hex') = $1)
        ),
        sale_family(root_covenant_id, covenant_id) AS (
            SELECT covenant_id, covenant_id
            FROM owner_sale
            UNION
            SELECT sf.root_covenant_id, child.covenant_id
            FROM sale_family sf
            JOIN covenant_actions parent_spend
              ON parent_spend.covenant_id = sf.covenant_id
             AND parent_spend.action = 'spend'
            JOIN covenants child
              ON child.genesis_txid = parent_spend.txid
            WHERE COALESCE(child.template_name, child.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND child.claim_verified = TRUE
        ),
        legacy_asks AS (
            SELECT
                encode(s.covenant_id, 'hex') AS order_id,
                'ask'::TEXT                  AS side,
                'open'::TEXT                 AS status,
                COALESCE(s.args->>'tokenId', s.args->>'listingTokenId') AS token_id_hex,
                COALESCE(s.args->>'seller', s.args->>'listingSeller')    AS owner,
                COALESCE(s.args->>'tokenAmount', s.args->>'listingTokenAmount') AS token_amount,
                SUM((COALESCE(tu.state->>'stateAmount', tu.state->>'amount'))::NUMERIC)::TEXT
                                                AS remaining_token_amount,
                COALESCE(s.args->>'priceSompi', s.args->>'listingPriceSompi') AS price_sompi,
                NULL::TEXT                     AS unit_price_sompi,
                NULL::TEXT                     AS min_fill_amount,
                s.template_name                AS template_name,
                s.address                      AS address,
                NULL::TEXT                     AS txid_hex,
                NULL::INT                      AS vout,
                NULL::TEXT                     AS close_txid_hex,
                NULL::TEXT                     AS close_entrypoint,
                s.created_at_ms                AS created_at_ms
            FROM owner_sale s
            JOIN sale_family suf
              ON suf.root_covenant_id = s.covenant_id
            JOIN covenant_utxos su
              ON su.covenant_id = suf.covenant_id
             AND su.status = 'active'
            JOIN covenant_utxos tu
              ON tu.covenant_id = decode(COALESCE(s.args->>'tokenId', s.args->>'listingTokenId'), 'hex')
             AND tu.status = 'active'
             AND COALESCE(tu.state->>'stateOwner', tu.state->>'ownerIdentifier') = encode(s.covenant_id, 'hex')
             AND (COALESCE(tu.state->>'stateOwnerType', tu.state->>'identifierType'))::INT = 2
            GROUP BY s.covenant_id, s.address, s.template_name, s.args, s.created_at_ms
        ),
        orderbook_asks AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'ask'::TEXT                                  AS side,
                'open'::TEXT                                 AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                               AS token_id_hex,
                u.state->>'ownerIdentifier'                  AS owner,
                u.state->>'amount'                           AS token_amount,
                u.state->>'amount'                           AS remaining_token_amount,
                ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                                                               AS price_sompi,
                u.state->>'unitPriceSompi'                   AS unit_price_sompi,
                u.state->>'minFillAmount'                    AS min_fill_amount,
                CASE
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END                                           AS template_name,
                u.address                                    AS address,
                encode(u.txid, 'hex')                        AS txid_hex,
                u.vout                                       AS vout,
                NULL::TEXT                                   AS close_txid_hex,
                NULL::TEXT                                   AS close_entrypoint,
                b.timestamp_ms                               AS created_at_ms
            FROM covenant_utxos u
            JOIN covenants c
              ON c.covenant_id = u.covenant_id
            JOIN blocks b
              ON b.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
              )
              AND u.state ? 'ownerIdentifier'
              AND u.state ? 'mode'
              AND u.state->>'mode' = '2'
              AND u.state->>'ownerIdentifier' = $2
              AND (
                  $1::BYTEA IS NULL
                  OR u.covenant_id = $1
                  OR (
                      NULLIF(u.state->>'canonicalTokenId', '') ~ '^[0-9a-fA-F]{64}$'
                      AND decode(u.state->>'canonicalTokenId', 'hex') = $1
                  )
              )
        ),
        bid_raw AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder')
              AND claim_verified = TRUE
              AND COALESCE(constructor_args->>'buyer', constructor_args->>'orderBuyer') = $2

            UNION ALL

            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder')
              AND claim_verified = TRUE
              AND (constructor_args IS NULL OR constructor_args = 'null'::jsonb)
              AND EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      CASE
                          WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                          ELSE '[]'::jsonb
                      END
                  ) AS arg
                  WHERE arg->>'name' IN ('buyer', 'orderBuyer')
                    AND arg->>'value' = $2
              )
        ),
        bid AS (
            SELECT
                covenant_id,
                script_hash,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM bid_raw
        ),
        owner_bid AS (
            SELECT *
            FROM bid
            WHERE COALESCE(args->>'buyer', args->>'orderBuyer') = $2
              AND COALESCE(args->>'tokenId', args->>'orderedTokenId') ~ '^[0-9a-fA-F]{64}$'
              AND ($1::BYTEA IS NULL OR decode(COALESCE(args->>'tokenId', args->>'orderedTokenId'), 'hex') = $1)
        ),
        legacy_bids AS (
            SELECT
                encode(b.covenant_id, 'hex') AS order_id,
                'bid'::TEXT                  AS side,
                'open'::TEXT                 AS status,
                COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId') AS token_id_hex,
                COALESCE(b.args->>'buyer', b.args->>'orderBuyer') AS owner,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS token_amount,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS remaining_token_amount,
                COALESCE(b.args->>'priceSompi', b.args->>'offerPriceSompi') AS price_sompi,
                NULL::TEXT                   AS unit_price_sompi,
                NULL::TEXT                   AS min_fill_amount,
                b.template_name              AS template_name,
                b.address                    AS address,
                NULL::TEXT                   AS txid_hex,
                NULL::INT                    AS vout,
                NULL::TEXT                   AS close_txid_hex,
                NULL::TEXT                   AS close_entrypoint,
                b.created_at_ms              AS created_at_ms
            FROM owner_bid b
            JOIN covenant_utxos bu
              ON bu.covenant_id = b.covenant_id
             AND bu.status = 'active'
            GROUP BY b.covenant_id, b.address, b.template_name, b.args, b.created_at_ms
        ),
        orderbook_bids AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'bid'::TEXT                                  AS side,
                'open'::TEXT                                 AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex'))
                                                               AS token_id_hex,
                u.state->>'ownerIdentifier'                  AS owner,
                u.state->>'amount'                           AS token_amount,
                u.state->>'amount'                           AS remaining_token_amount,
                ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                                                               AS price_sompi,
                u.state->>'unitPriceSompi'                   AS unit_price_sompi,
                u.state->>'minFillAmount'                    AS min_fill_amount,
                CASE
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END                                           AS template_name,
                u.address                                    AS address,
                encode(u.txid, 'hex')                        AS txid_hex,
                u.vout                                       AS vout,
                NULL::TEXT                                   AS close_txid_hex,
                NULL::TEXT                                   AS close_entrypoint,
                blk.timestamp_ms                             AS created_at_ms
            FROM covenant_utxos u
            JOIN covenants c
              ON c.covenant_id = u.covenant_id
            JOIN blocks blk
              ON blk.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
              )
              AND u.state ? 'ownerIdentifier'
              AND u.state ? 'mode'
              AND u.state->>'mode' = '3'
              AND u.state->>'ownerIdentifier' = $2
              AND (
                  $1::BYTEA IS NULL
                  OR u.covenant_id = $1
                  OR (
                      NULLIF(u.state->>'canonicalTokenId', '') ~ '^[0-9a-fA-F]{64}$'
                      AND decode(u.state->>'canonicalTokenId', 'hex') = $1
                  )
              )
        ),
        orders AS (
            SELECT * FROM legacy_asks
            UNION ALL
            SELECT * FROM orderbook_asks
            UNION ALL
            SELECT * FROM legacy_bids
            UNION ALL
            SELECT * FROM orderbook_bids
        )
        SELECT *
        FROM orders
        ORDER BY created_at_ms DESC, order_id DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(token_id)
    .bind(owner)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(kcc20_owner_order_from_row).collect())
}

pub async fn kcc20_trades(
    pool: &PgPool,
    token_id_hex: Option<&str>,
    owner_hex: Option<&str>,
    side: Option<&str>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20TradeRow>> {
    let rows = sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH trades AS (
            SELECT
                COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(holder.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                encode(a.txid, 'hex')        AS txid_hex,
                a.block_time_ms              AS block_time_ms,
                a.entrypoint AS entrypoint,
                CASE
                    WHEN a.entrypoint = 'fillAskPartial' THEN 'buy'
                    WHEN a.entrypoint = 'fillBidPartial' THEN 'sell'
                    WHEN a.entrypoint = 'fillBidFromSellerSweep' THEN 'sell'
                    WHEN a.entrypoint = 'sellIntoBidByOwnerSig' THEN 'sell'
                    WHEN a.entrypoint IN ('crossAskSide', 'crossBidSide') THEN 'cross'
                    ELSE 'trade'
                END                          AS side,
                a.decoded_args->>'ownerIdentifier' AS maker,
                CASE
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide') THEN COALESCE(
                        NULLIF(seller_spend.decoded_args->>'ownerIdentifier', ''),
                        NULLIF(a.decoded_args->>'seller', ''),
                        holder.outputs->'state'->>'ownerIdentifier'
                    )
                    ELSE holder.outputs->'state'->>'ownerIdentifier'
                END AS taker,
                COALESCE(
                    NULLIF(a.decoded_args->>'fillAmount', ''),
                    holder.outputs->'state'->>'amount'
                ) AS token_amount,
                a.decoded_args->>'unitPriceSompi' AS unit_price_sompi,
                CASE
                    WHEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount') IS NOT NULL
                     AND a.decoded_args->>'unitPriceSompi' IS NOT NULL
                    THEN FLOOR(
                        COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount')::NUMERIC
                        * (a.decoded_args->>'unitPriceSompi')::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions holder
                WHERE holder.covenant_id = a.covenant_id
                  AND holder.txid = a.txid
                  AND holder.action = 'continuation'
                  AND holder.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (holder.outputs ? 'vout') DESC,
                  holder.id DESC
                LIMIT 1
            ) holder ON TRUE
            LEFT JOIN LATERAL (
                SELECT decoded_args
                FROM covenant_actions seller_spend
                WHERE seller_spend.covenant_id = a.covenant_id
                  AND seller_spend.txid = a.txid
                  AND seller_spend.action = 'spend'
                  AND NULLIF(a.decoded_args->>'sellerInputIndex', '') IS NOT NULL
                  AND seller_spend.decoded_args->>'inputIndex' = a.decoded_args->>'sellerInputIndex'
                ORDER BY seller_spend.id ASC
                LIMIT 1
            ) seller_spend ON TRUE
            WHERE (
                COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                OR a.decoded_args->>'supplyBacking' = 'kcc20WrapperReserve'
                OR a.decoded_args ? 'canonicalTokenId'
              )
              AND a.action = 'spend'
              AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
              AND NOT (
                a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__

            UNION ALL
            SELECT token_id_hex,txid_hex,block_time_ms,entrypoint,side,maker,taker,token_amount,unit_price_sompi,price_sompi FROM kcc20_fee_trade_executions

            UNION ALL

            SELECT
                COALESCE(
                    a.decoded_args->>'tokenId',
                    a.decoded_args->>'listingTokenId',
                    a.decoded_args->>'orderedTokenId'
                ) AS token_id_hex,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms       AS block_time_ms,
                a.entrypoint          AS entrypoint,
                CASE
                    WHEN a.entrypoint IN ('buy', 'buyListing') THEN 'buy'
                    WHEN a.entrypoint = 'fillBuyOrder' THEN 'sell'
                    ELSE 'trade'
                END AS side,
                COALESCE(
                    a.decoded_args->>'seller',
                    a.decoded_args->>'listingSeller',
                    a.decoded_args->>'buyer',
                    a.decoded_args->>'orderBuyer'
                ) AS maker,
                NULL::TEXT AS taker,
                COALESCE(
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount'
                ) AS token_amount,
                NULL::TEXT AS unit_price_sompi,
                COALESCE(
                    a.decoded_args->>'priceSompi',
                    a.decoded_args->>'listingPriceSompi',
                    a.decoded_args->>'offerPriceSompi'
                ) AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
              AND c.claim_verified = TRUE
              AND a.action = 'spend'
              AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        )
        SELECT *
        FROM trades
        WHERE token_id_hex IS NOT NULL
          AND ($1::TEXT IS NULL OR token_id_hex = $1)
          AND ($2::TEXT IS NULL OR maker = $2 OR taker = $2)
          AND (
              $3::TEXT IS NULL
              OR $3 = 'trade'
              OR side = $3
          )
          AND ($4::BIGINT IS NULL OR block_time_ms >= $4)
          AND ($5::BIGINT IS NULL OR block_time_ms < $5)
        ORDER BY block_time_ms DESC, txid_hex DESC
        LIMIT $6 OFFSET $7
        "#,
        )))
    .bind(token_id_hex)
    .bind(owner_hex)
    .bind(side)
    .bind(from_ms)
    .bind(to_ms)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Kcc20TradeRow {
            token_id_hex: r.get("token_id_hex"),
            txid_hex: r.get("txid_hex"),
            block_time_ms: r.get("block_time_ms"),
            entrypoint: r.get("entrypoint"),
            side: r.get("side"),
            maker: r.get("maker"),
            taker: r.get("taker"),
            token_amount: r.get("token_amount"),
            unit_price_sompi: r.get("unit_price_sompi"),
            price_sompi: r.get("price_sompi"),
        })
        .collect())
}

pub async fn kcc20_trade_summaries(pool: &PgPool) -> Result<Vec<Kcc20TradeSummaryRow>> {
    let rows = sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH trades AS (
            SELECT
                COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(holder.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                encode(a.txid, 'hex')        AS txid_hex,
                a.block_time_ms              AS block_time_ms,
                CASE
                    WHEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount') IS NOT NULL
                     AND a.decoded_args->>'unitPriceSompi' IS NOT NULL
                    THEN FLOOR(
                        COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount')::NUMERIC
                        * (a.decoded_args->>'unitPriceSompi')::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions holder
                WHERE holder.covenant_id = a.covenant_id
                  AND holder.txid = a.txid
                  AND holder.action = 'continuation'
                  AND holder.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (holder.outputs ? 'vout') DESC,
                  holder.id DESC
                LIMIT 1
            ) holder ON TRUE
            WHERE (
                COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                OR a.decoded_args->>'supplyBacking' = 'kcc20WrapperReserve'
                OR a.decoded_args ? 'canonicalTokenId'
              )
              AND a.action = 'spend'
              AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
              AND NOT (
                a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__

            UNION ALL
            SELECT token_id_hex,txid_hex,block_time_ms,price_sompi FROM kcc20_fee_trade_executions

            UNION ALL

            SELECT
                COALESCE(
                    a.decoded_args->>'tokenId',
                    a.decoded_args->>'listingTokenId',
                    a.decoded_args->>'orderedTokenId'
                ) AS token_id_hex,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms       AS block_time_ms,
                COALESCE(
                    a.decoded_args->>'priceSompi',
                    a.decoded_args->>'listingPriceSompi',
                    a.decoded_args->>'offerPriceSompi'
                ) AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
              AND c.claim_verified = TRUE
              AND a.action = 'spend'
              AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        ),
        ranked AS (
            SELECT
                token_id_hex,
                txid_hex,
                block_time_ms,
                price_sompi,
                ROW_NUMBER() OVER (PARTITION BY token_id_hex ORDER BY block_time_ms DESC, txid_hex DESC) AS rn
            FROM trades
            WHERE token_id_hex IS NOT NULL
        )
        SELECT
            token_id_hex,
            COALESCE(SUM(
                CASE
                    WHEN price_sompi ~ '^[0-9]+$' THEN price_sompi::NUMERIC
                    ELSE 0
                END
            ), 0)::TEXT AS total_volume_sompi,
            COUNT(*)::BIGINT AS total_trades,
            MAX(txid_hex) FILTER (WHERE rn = 1) AS last_trade_txid_hex,
            MAX(block_time_ms) FILTER (WHERE rn = 1) AS last_trade_time_ms
        FROM ranked
        GROUP BY token_id_hex
        ORDER BY total_trades DESC, last_trade_time_ms DESC NULLS LAST
        LIMIT 1001
        "#,
        )))
    .fetch_all(pool)
    .await?;
    if rows.len() > KCC20_TRADE_SUMMARY_MAX_ROWS {
        anyhow::bail!(
            "KCC20 trade summary query exceeds the safe {} row limit",
            KCC20_TRADE_SUMMARY_MAX_ROWS
        );
    }

    Ok(rows
        .into_iter()
        .map(|r| Kcc20TradeSummaryRow {
            token_id_hex: r.get("token_id_hex"),
            total_volume_sompi: r.get("total_volume_sompi"),
            total_trades: r.get("total_trades"),
            last_trade_txid_hex: r.get("last_trade_txid_hex"),
            last_trade_time_ms: r.get("last_trade_time_ms"),
        })
        .collect())
}

/// Requires owner orders to have been refreshed through the same dirty pass.
pub async fn refresh_kcc20_market_summaries(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    // This indexed projection is cheaper to execute than to JIT-compile.
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL lock_timeout = '2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '15s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_market_summaries_refresh', 0))",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM kcc20_market_summaries")
        .execute(&mut *tx)
        .await?;
    sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH
        orderbook_trade_actions AS MATERIALIZED (
            SELECT * FROM covenant_actions
            WHERE action = 'spend'
              AND entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
        ),
        -- The ordered owner-orders phase has already resolved which order
        -- UTXOs are open and authenticated. Keep the market's trade scan here,
        -- but derive open prices and counts from those indexed order rows.
        open_asks AS (
            SELECT
                encode(token_id, 'hex') AS token_id_hex,
                CASE
                    WHEN unit_price_sompi ~ '^[0-9]+$'
                        THEN unit_price_sompi::NUMERIC
                    WHEN template_name IN ('KCC20Sale', 'KCC20SaleV2')
                     AND price_sompi ~ '^[0-9]+$'
                     AND token_amount ~ '^[0-9]+$'
                        THEN price_sompi::NUMERIC / NULLIF(token_amount::NUMERIC, 0)
                    ELSE NULL
                END AS unit_price_sompi
            FROM kcc20_owner_orders
            WHERE status = 'open' AND side = 'ask'
        ),
        open_bids AS (
            SELECT
                encode(token_id, 'hex') AS token_id_hex,
                CASE
                    WHEN unit_price_sompi ~ '^[0-9]+$'
                        THEN unit_price_sompi::NUMERIC
                    WHEN template_name = 'KCC20BuyOrder'
                     AND price_sompi ~ '^[0-9]+$'
                     AND token_amount ~ '^[0-9]+$'
                        THEN price_sompi::NUMERIC / NULLIF(token_amount::NUMERIC, 0)
                    ELSE NULL
                END AS unit_price_sompi
            FROM kcc20_owner_orders
            WHERE status = 'open' AND side = 'bid'
        ),
        raw_trades AS (
            SELECT
                COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(holder.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                a.txid AS txid,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms,
                CASE
                    WHEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount') IS NOT NULL
                     AND a.decoded_args->>'unitPriceSompi' ~ '^[0-9]+$'
                    THEN FLOOR(COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount')::NUMERIC
                       * (a.decoded_args->>'unitPriceSompi')::NUMERIC
                       / GREATEST(COALESCE(NULLIF(holder.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1))
                    ELSE NULL
                END AS price_sompi
            FROM orderbook_trade_actions a
            -- Keep sparse trade lookups from hashing the entire covenant registry.
            CROSS JOIN LATERAL (
                SELECT * FROM covenants candidate
                WHERE candidate.covenant_id = a.covenant_id
                OFFSET 0
            ) c
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions holder
                WHERE holder.covenant_id = a.covenant_id
                  AND holder.txid = a.txid
                  AND holder.action = 'continuation'
                  AND holder.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (holder.outputs ? 'vout') DESC,
                  holder.id DESC
                LIMIT 1
            ) holder ON TRUE
            WHERE (
                COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                OR a.decoded_args->>'supplyBacking' = 'kcc20WrapperReserve'
                OR a.decoded_args ? 'canonicalTokenId'
              )
              AND a.action = 'spend'
              AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
              AND NOT (
                a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__

            UNION ALL
            SELECT token_id_hex,txid,txid_hex,block_time_ms,price_sompi::NUMERIC FROM kcc20_fee_trade_executions

            UNION ALL

            SELECT
                COALESCE(
                    a.decoded_args->>'tokenId',
                    a.decoded_args->>'listingTokenId',
                    a.decoded_args->>'orderedTokenId'
                ) AS token_id_hex,
                a.txid AS txid,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms,
                CASE
                    WHEN COALESCE(
                        a.decoded_args->>'priceSompi',
                        a.decoded_args->>'listingPriceSompi',
                        a.decoded_args->>'offerPriceSompi'
                    ) ~ '^[0-9]+$'
                    THEN COALESCE(
                        a.decoded_args->>'priceSompi',
                        a.decoded_args->>'listingPriceSompi',
                        a.decoded_args->>'offerPriceSompi'
                    )::NUMERIC
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
              AND c.claim_verified = TRUE
              AND a.action = 'spend'
              AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        ),
        ranked_trades AS (
            SELECT
                lower(token_id_hex) AS token_id_hex,
                txid,
                txid_hex,
                block_time_ms,
                price_sompi,
                ROW_NUMBER() OVER (
                    PARTITION BY lower(token_id_hex)
                    ORDER BY block_time_ms DESC, txid_hex DESC
                ) AS rn
            FROM raw_trades
            WHERE token_id_hex ~ '^[0-9a-fA-F]{64}$'
        ),
        ask_summary AS (
            SELECT lower(token_id_hex) AS token_id_hex, MIN(unit_price_sompi) AS best_ask, COUNT(*)::BIGINT AS asks
            FROM open_asks
            WHERE token_id_hex ~ '^[0-9a-fA-F]{64}$'
            GROUP BY lower(token_id_hex)
        ),
        bid_summary AS (
            SELECT lower(token_id_hex) AS token_id_hex, MAX(unit_price_sompi) AS best_bid, COUNT(*)::BIGINT AS bids
            FROM open_bids
            WHERE token_id_hex ~ '^[0-9a-fA-F]{64}$'
            GROUP BY lower(token_id_hex)
        ),
        trade_summary AS (
            SELECT
                token_id_hex,
                COALESCE(SUM(COALESCE(price_sompi, 0)), 0) AS total_volume,
                COUNT(*)::BIGINT AS total_trades,
                decode(MAX(txid_hex) FILTER (WHERE rn = 1), 'hex') AS last_trade_txid,
                MAX(block_time_ms) FILTER (WHERE rn = 1) AS last_trade_time_ms
            FROM ranked_trades
            GROUP BY token_id_hex
        ),
        anchor AS MATERIALIZED (
            SELECT COALESCE(
                (SELECT timestamp_ms FROM blocks WHERE is_chain_block ORDER BY blue_score DESC LIMIT 1),
                (SELECT timestamp_ms FROM blocks ORDER BY blue_score DESC LIMIT 1),
                (SELECT MAX(block_time_ms) FROM ranked_trades),
                0
            ) AS anchor_ms
        ),
        window_summary AS (
            SELECT
                rt.token_id_hex,
                COALESCE(SUM(COALESCE(rt.price_sompi, 0)) FILTER (
                    WHERE rt.block_time_ms >= anchor.anchor_ms - 86400000
                ), 0) AS volume_24h,
                COALESCE(SUM(COALESCE(rt.price_sompi, 0)) FILTER (
                    WHERE rt.block_time_ms >= anchor.anchor_ms - 604800000
                ), 0) AS volume_7d,
                COUNT(*) FILTER (
                    WHERE rt.block_time_ms >= anchor.anchor_ms - 86400000
                )::BIGINT AS trades_24h,
                COUNT(*) FILTER (
                    WHERE rt.block_time_ms >= anchor.anchor_ms - 604800000
                )::BIGINT AS trades_7d
            FROM ranked_trades rt
            CROSS JOIN anchor
            GROUP BY rt.token_id_hex
        ),
        tokens AS (
            SELECT token_id_hex FROM ask_summary
            UNION
            SELECT token_id_hex FROM bid_summary
            UNION
            SELECT token_id_hex FROM trade_summary
        ),
        freshness AS (
            SELECT
                (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) AS refreshed_at_ms,
                MAX(blue_score) AS source_blue_score
            FROM blocks
            WHERE is_chain_block
        )
        INSERT INTO kcc20_market_summaries (
            token_id,
            best_ask_unit_price_sompi,
            best_bid_unit_price_sompi,
            spread_sompi,
            open_ask_count,
            open_bid_count,
            total_volume_sompi,
            total_trades,
            last_trade_txid,
            last_trade_time_ms,
            refreshed_at_ms,
            source_blue_score,
            volume_24h_sompi,
            volume_7d_sompi,
            trade_count_24h,
            trade_count_7d
        )
        SELECT
            decode(t.token_id_hex, 'hex'),
            a.best_ask,
            b.best_bid,
            CASE WHEN a.best_ask IS NOT NULL AND b.best_bid IS NOT NULL
                 THEN a.best_ask - b.best_bid
                 ELSE NULL
            END,
            COALESCE(a.asks, 0),
            COALESCE(b.bids, 0),
            COALESCE(ts.total_volume, 0),
            COALESCE(ts.total_trades, 0),
            ts.last_trade_txid,
            ts.last_trade_time_ms,
            f.refreshed_at_ms,
            f.source_blue_score,
            COALESCE(ws.volume_24h, 0),
            COALESCE(ws.volume_7d, 0),
            COALESCE(ws.trades_24h, 0),
            COALESCE(ws.trades_7d, 0)
        FROM tokens t
        CROSS JOIN freshness f
        LEFT JOIN ask_summary a ON a.token_id_hex = t.token_id_hex
        LEFT JOIN bid_summary b ON b.token_id_hex = t.token_id_hex
        LEFT JOIN trade_summary ts ON ts.token_id_hex = t.token_id_hex
        LEFT JOIN window_summary ws ON ws.token_id_hex = t.token_id_hex
        "#,
        )))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn kcc20_market_summaries_table_exists(pool: &PgPool) -> Result<bool> {
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('kcc20_market_summaries') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    Ok(exists)
}

async fn table_exists(pool: &PgPool, table_name: &str) -> Result<bool> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table_name)
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

pub async fn kcc20_token_page_projection_tables_exist(pool: &PgPool) -> Result<bool> {
    Ok(table_exists(pool, "kcc20_activity_feed").await?
        && table_exists(pool, "kcc20_wrapper_summaries").await?
        && table_exists(pool, "kcc20_token_summaries").await?)
}

pub async fn kcc20_owner_portfolio_assets_table_exists(pool: &PgPool) -> Result<bool> {
    table_exists(pool, "kcc20_owner_portfolio_assets").await
}

pub async fn kcc20_owner_orders_table_exists(pool: &PgPool) -> Result<bool> {
    table_exists(pool, "kcc20_owner_orders").await
}

pub async fn kcc20_owner_orders_initialized(pool: &PgPool) -> Result<bool> {
    let initialized = sqlx::query_scalar(
        r#"
        SELECT to_regclass('kcc20_owner_orders') IS NOT NULL
           AND EXISTS (
               SELECT 1
               FROM kcc20_projection_state state
               WHERE state.name = $1
                 AND state.refreshed_at_ms IS NOT NULL
                 AND state.last_dirty_id >= COALESCE((
                     SELECT MAX(dirty.id)
                     FROM kcc20_projection_dirty dirty
                     WHERE dirty.reason = 'owner_orders_projection_added'
                 ), 0)
           )
        "#,
    )
    .bind(KCC20_OWNER_ORDERS_PROJECTION)
    .fetch_one(pool)
    .await?;
    Ok(initialized)
}

pub async fn kcc20_owner_portfolio_assets_initialized(pool: &PgPool) -> Result<bool> {
    let initialized = sqlx::query_scalar(
        r#"
        SELECT to_regclass('kcc20_owner_portfolio_assets') IS NOT NULL
           AND EXISTS (
               SELECT 1
               FROM kcc20_projection_state state
               WHERE state.name = $1
                 AND state.refreshed_at_ms IS NOT NULL
                 AND state.last_dirty_id >= COALESCE((
                     SELECT MAX(dirty.id)
                     FROM kcc20_projection_dirty dirty
                     WHERE dirty.reason = 'kcc20_standard_native_cutover'
                 ), 0)
           )
        "#,
    )
    .bind(KCC20_OWNER_PORTFOLIO_ASSETS_PROJECTION)
    .fetch_one(pool)
    .await?;
    Ok(initialized)
}

pub async fn refresh_kcc20_token_page_projections(pool: &PgPool) -> Result<()> {
    if !kcc20_token_page_projection_tables_exist(pool).await? {
        return Ok(());
    }

    refresh_kcc20_wrapper_summaries(pool).await?;
    run_kcc20_repair_step("wrapper_action_canonical_token_ids", || async {
        repair_kcc20_wrapper_action_canonical_token_ids(pool).await
    })
    .await;
    run_kcc20_repair_step("wrapper_claim_verification", || async {
        repair_kcc20_wrapper_claim_verification(pool).await
    })
    .await;
    refresh_kcc20_token_summaries(pool).await?;
    Ok(())
}

pub async fn refresh_kcc20_token_page_repairs_best_effort(pool: &PgPool) -> Result<u64> {
    if !kcc20_token_page_projection_tables_exist(pool).await? {
        return Ok(0);
    }

    let mut updated = 0;
    updated += run_kcc20_repair_step("wrapper_action_canonical_token_ids", || async {
        repair_kcc20_wrapper_action_canonical_token_ids(pool).await
    })
    .await;
    updated += run_kcc20_repair_step("wrapper_claim_verification", || async {
        repair_kcc20_wrapper_claim_verification(pool).await
    })
    .await;
    Ok(updated)
}

async fn run_kcc20_repair_step<F, Fut>(name: &'static str, f: F) -> u64
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<u64>>,
{
    match f().await {
        Ok(updated) if updated > 0 => {
            tracing::info!(
                target: "kcc20_projector",
                repair = name,
                updated,
                "KCC20 projection repair batch completed"
            );
            updated
        }
        Ok(_) => 0,
        Err(error) => {
            tracing::warn!(
                target: "kcc20_projector",
                repair = name,
                error = %error,
                "KCC20 projection repair batch failed; will retry later"
            );
            0
        }
    }
}

pub async fn repair_kcc20_wrapper_action_canonical_token_ids(pool: &PgPool) -> Result<u64> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "500ms", "5s").await?;
    let rows_affected = sqlx::query(
        r#"
        WITH target AS (
            SELECT a.id, w.canonical_token_id
            FROM covenant_actions a
            JOIN covenants c
              ON c.covenant_id = a.covenant_id
            JOIN kcc20_wrapper_summaries w
              ON w.wrapper_id = c.covenant_id
            WHERE (c.template_name = 'KCC20Wrapper'
               OR c.claimed_template = 'KCC20Wrapper')
              AND a.canonical_token_id IS DISTINCT FROM w.canonical_token_id
            ORDER BY a.id
            LIMIT $1
            FOR UPDATE OF a SKIP LOCKED
        )
        UPDATE covenant_actions a
        SET canonical_token_id = target.canonical_token_id
        FROM target
        WHERE a.id = target.id
        "#,
    )
    .bind(KCC20_REPAIR_BATCH_LIMIT)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(rows_affected)
}

pub async fn repair_kcc20_wrapper_claim_verification(pool: &PgPool) -> Result<u64> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "500ms", "5s").await?;
    let rows_affected = sqlx::query(
        r#"
        WITH claimed AS (
            SELECT
                c.covenant_id,
                lower(args->>'canonicalTokenId') AS claimed_canonical_hex
            FROM covenants c
            CROSS JOIN LATERAL (
                SELECT jsonb_object_agg(arg->>'name', arg->'value') AS args
                FROM jsonb_array_elements(
                    CASE
                        WHEN jsonb_typeof(c.claimed_args->'args') = 'array'
                        THEN c.claimed_args->'args'
                        ELSE '[]'::jsonb
                    END
                ) AS arg
            ) claim_args
            WHERE (c.template_name = 'KCC20Wrapper'
               OR c.claimed_template = 'KCC20Wrapper')
              AND c.claimed_args IS NOT NULL
              AND c.claim_verified = FALSE
            ORDER BY c.created_at_ms, c.covenant_id
            LIMIT $1
        ),
        verified AS (
            SELECT c.covenant_id
            FROM claimed c
            JOIN kcc20_wrapper_summaries w
              ON w.wrapper_id = c.covenant_id
            WHERE c.claimed_canonical_hex ~ '^[0-9a-f]{64}$'
              AND c.claimed_canonical_hex = encode(w.canonical_token_id, 'hex')
        )
        UPDATE covenants c
        SET claim_verified = TRUE,
            claim_verified_at_ms = (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
        FROM verified v
        WHERE c.covenant_id = v.covenant_id
        "#,
    )
    .bind(KCC20_REPAIR_BATCH_LIMIT)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(rows_affected)
}

pub async fn refresh_kcc20_wrapper_summaries(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "2s", "20s").await?;
    sqlx::query("SELECT set_config('jit', 'off', true)")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_wrapper_summaries_refresh', 0))",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        WITH freshness AS MATERIALIZED (
            SELECT
                (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) AS refreshed_at_ms,
                blue_score AS source_blue_score
            FROM blocks
            WHERE is_chain_block
            ORDER BY blue_score DESC
            LIMIT 1
        ),
        wrapper_base AS MATERIALIZED (
            SELECT
                c.covenant_id AS wrapper_id,
                COALESCE(
                    (
                        SELECT u.address
                        FROM covenant_utxos u
                        JOIN blocks b ON b.hash = u.created_block
                        WHERE u.covenant_id = c.covenant_id
                          AND u.status = 'active'
                          AND u.state ? 'enabled'
                          AND u.state ? 'priceScale'
                        ORDER BY b.blue_score DESC, u.txid DESC, u.vout DESC
                        LIMIT 1
                    ),
                    c.address
                ) AS address,
                c.genesis_txid,
                c.classification_kind,
                c.classification_status,
                c.claim_source,
                c.constructor_args,
                c.claimed_args
            FROM covenants c
            WHERE c.template_name = 'KCC20Wrapper'
               OR c.claimed_template = 'KCC20Wrapper'
        ),
        active_utxo_counts AS (
            SELECT
                w.wrapper_id,
                COUNT(active_utxo.txid)::BIGINT AS active_utxos
            FROM wrapper_base w
            LEFT JOIN LATERAL (
                SELECT u.txid
                FROM covenant_utxos u
                WHERE u.covenant_id = w.wrapper_id
                  AND u.status = 'active'
                OFFSET 0
            ) active_utxo ON TRUE
            GROUP BY w.wrapper_id
        ),
        wrapper_owners AS (
            SELECT
                w.wrapper_id,
                w.wrapper_id AS owner_identifier
            FROM wrapper_base w

            UNION

            SELECT
                w.wrapper_id,
                owner.owner_identifier
            FROM wrapper_base w
            CROSS JOIN LATERAL (
                SELECT decode(u.state->>'wrapperCovenantId', 'hex') AS owner_identifier
                FROM covenant_utxos u
                WHERE u.covenant_id = w.wrapper_id
                  AND u.status = 'active'
                  AND u.state->>'wrapperCovenantId' ~ '^[0-9a-fA-F]{64}$'
                OFFSET 0
            ) owner
        ),
        reserves AS (
            SELECT DISTINCT ON (owners.wrapper_id)
                owners.wrapper_id,
                h.covenant_id AS canonical_token_id
            FROM wrapper_owners owners
            JOIN kcc20_holders h
              ON h.owner_identifier = owners.owner_identifier
            WHERE h.identifier_type = 4
              AND h.is_minter = FALSE
            ORDER BY
                owners.wrapper_id,
                (h.amount_total > 0) DESC,
                h.amount_total DESC,
                h.covenant_id ASC
        ),
        wrapper_rows AS (
            SELECT
                w.wrapper_id,
                w.address,
                w.genesis_txid,
                w.classification_kind,
                w.classification_status,
                w.claim_source,
                COALESCE(active.active_utxos, 0) AS active_utxos,
                reserve.canonical_token_id AS reserve_canonical_token_id,
                COALESCE(
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(w.claimed_args->'args') = 'array'
                                THEN w.claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    ),
                    NULLIF(w.constructor_args, 'null'::jsonb),
                    '{}'::jsonb
                ) AS args
            FROM wrapper_base w
            LEFT JOIN active_utxo_counts active
              ON active.wrapper_id = w.wrapper_id
            LEFT JOIN reserves reserve
              ON reserve.wrapper_id = w.wrapper_id
        ),
        normalized AS (
            SELECT
                wrapper_id,
                address,
                genesis_txid,
                active_utxos,
                classification_kind,
                classification_status,
                claim_source,
                COALESCE(
                    encode(reserve_canonical_token_id, 'hex'),
                    lower(args->>'canonicalTokenId')
                ) AS canonical_token_id_hex,
                lower(args->>'feeTicketId') AS fee_ticket_id_hex,
                NULLIF(args->>'wrappedRootAmount', '') AS wrapped_root_amount,
                CASE
                    WHEN lower(args->>'initEnabled') IN ('true', 'false')
                    THEN (args->>'initEnabled')::BOOLEAN
                    WHEN lower(args->>'enabled') IN ('true', 'false')
                    THEN (args->>'enabled')::BOOLEAN
                    ELSE TRUE
                END AS enabled
            FROM wrapper_rows
        )
        INSERT INTO kcc20_wrapper_summaries (
            wrapper_id, canonical_token_id, address, genesis_txid, active_utxos,
            pending_reveal, enabled, fee_ticket_id, wrapped_root_amount,
            classification_kind, classification_status, claim_source,
            refreshed_at_ms, source_blue_score
        )
        SELECT
            n.wrapper_id,
            decode(n.canonical_token_id_hex, 'hex'),
            n.address,
            n.genesis_txid,
            n.active_utxos,
            n.classification_status = 'unrevealed'
              AND n.classification_kind = 'unknown'
              AND COALESCE(n.claim_source, '') = 'payload'
              AND n.active_utxos > 0,
            n.enabled,
            CASE
                WHEN n.fee_ticket_id_hex ~ '^[0-9a-f]{64}$'
                THEN decode(n.fee_ticket_id_hex, 'hex')
                ELSE NULL
            END,
            CASE
                WHEN n.wrapped_root_amount ~ '^[0-9]+$'
                THEN n.wrapped_root_amount::NUMERIC
                ELSE NULL
            END,
            n.classification_kind,
            n.classification_status,
            n.claim_source,
            f.refreshed_at_ms,
            f.source_blue_score
        FROM normalized n
        CROSS JOIN freshness f
        WHERE n.canonical_token_id_hex ~ '^[0-9a-f]{64}$'
        ON CONFLICT (wrapper_id) DO UPDATE SET
            canonical_token_id = EXCLUDED.canonical_token_id,
            address = EXCLUDED.address,
            genesis_txid = EXCLUDED.genesis_txid,
            active_utxos = EXCLUDED.active_utxos,
            pending_reveal = EXCLUDED.pending_reveal,
            enabled = EXCLUDED.enabled,
            fee_ticket_id = EXCLUDED.fee_ticket_id,
            wrapped_root_amount = EXCLUDED.wrapped_root_amount,
            classification_kind = EXCLUDED.classification_kind,
            classification_status = EXCLUDED.classification_status,
            claim_source = EXCLUDED.claim_source,
            refreshed_at_ms = EXCLUDED.refreshed_at_ms,
            source_blue_score = EXCLUDED.source_blue_score
        "#,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        DELETE FROM kcc20_wrapper_summaries s
        WHERE NOT EXISTS (
            SELECT 1 FROM covenants c
            WHERE c.covenant_id = s.wrapper_id
              AND (
                  c.template_name = 'KCC20Wrapper'
                  OR c.claimed_template = 'KCC20Wrapper'
              )
        )
        "#,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn refresh_kcc20_token_summaries(pool: &PgPool) -> Result<()> {
    // A repeatable-read snapshot predates any wait for the refresh lock. Retry
    // the whole snapshot when an overlapping refresher commits first.
    for attempt in 0..3 {
        match refresh_kcc20_token_summaries_snapshot(pool).await {
            Err(error) if attempt < 2 && error.downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(|db| db.code()).as_deref() == Some("40001") => continue,
            result => return result,
        }
    }
    unreachable!("the final attempt returns its result")
}

async fn refresh_kcc20_token_summaries_snapshot(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    // Authenticate wrappers and sum their balances from the same database snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    set_local_query_limits(&mut tx, "2s", "20s").await?;
    // This snapshot has a tiny indexed working set; JIT setup costs more than
    // execution and can make the projector hold its transaction for seconds.
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_token_summaries_refresh', 0))",
    )
    .execute(&mut *tx)
    .await?;

    let fee_wrappers: Vec<Value> = authenticated_fee_wrapper_rows(&mut tx, None)
        .await?
        .into_iter()
        .map(|row| {
            // Authentication above proves the exact 35-byte P2SH program.
            let script = row.get::<Vec<u8>, _>("wrapper_script_pubkey");
            json!({
                "token_id": row.get::<String, _>("canonical_token_id"),
                "wrapper_id": row.get::<String, _>("market_id_hex"),
                "reserve_owner": hex::encode(&script[2..34]),
            })
        })
        .collect();
    let fee_wrappers = json!(fee_wrappers);
    sqlx::query(include_str!("queries/kcc20_token_summaries.sql"))
        .bind(&fee_wrappers)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        r#"
        DELETE FROM kcc20_token_summaries s
        WHERE NOT EXISTS (SELECT 1 FROM kcc20_holders h WHERE h.covenant_id = s.token_id)
          AND NOT EXISTS (SELECT 1 FROM kcc20_wrapper_summaries w WHERE w.canonical_token_id = s.token_id)
          AND NOT EXISTS (SELECT 1 FROM kcc20_market_summaries m WHERE m.token_id = s.token_id)
          AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements($1::JSONB) w
              WHERE w->>'token_id' = encode(s.token_id, 'hex')
          )
        "#,
    )
    .bind(&fee_wrappers)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn refresh_kcc20_owner_orders(pool: &PgPool) -> Result<()> {
    if !kcc20_owner_orders_table_exists(pool).await? {
        anyhow::bail!("kcc20_owner_orders migration is required");
    }
    let timeout_secs = std::env::var("TN12_KCC20_OWNER_ORDERS_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120)
        .clamp(10, 600);
    let statement_timeout = format!("{timeout_secs}s");
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "2s", &statement_timeout).await?;
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_owner_orders_refresh', 0))",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM kcc20_owner_orders")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        WITH RECURSIVE freshness AS (
            SELECT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) AS refreshed_at_ms
        ),
        sale_raw AS (
            SELECT
                covenant_id,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20Sale', 'KCC20SaleV2')
              AND claim_verified = TRUE
        ),
        sale AS (
            SELECT
                covenant_id,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM sale_raw
        ),
        sale_edges AS MATERIALIZED (
            SELECT
                parent_spend.covenant_id AS parent_covenant_id,
                child.covenant_id AS child_covenant_id
            FROM covenant_actions parent_spend
            JOIN covenants parent ON parent.covenant_id = parent_spend.covenant_id
            JOIN covenants child ON child.genesis_txid = parent_spend.txid
             AND COALESCE(child.template_name, child.claimed_template)
                 IN ('KCC20Sale', 'KCC20SaleV2')
             AND child.claim_verified = TRUE
            CROSS JOIN LATERAL (
                SELECT CASE
                    WHEN parent_spend.decoded_args->>'listingOutputIndex' ~ '^[0-9]{1,10}$'
                    THEN (parent_spend.decoded_args->>'listingOutputIndex')::BIGINT
                    ELSE NULL::BIGINT
                END AS listing_output_vout
            ) activation
            WHERE parent_spend.action = 'spend'
              AND COALESCE(parent.template_name, parent.claimed_template) = 'KCC20SaleV2'
              AND parent.claim_verified = TRUE
              AND parent_spend.entrypoint = 'activateListing'
              AND (
                  (activation.listing_output_vout BETWEEN 0 AND 2147483647
                   AND child.genesis_vout = activation.listing_output_vout)
                  OR (activation.listing_output_vout IS NULL
                   AND 1 = (
                       SELECT COUNT(*) FROM covenants sibling
                       WHERE sibling.genesis_txid = parent_spend.txid
                         AND COALESCE(sibling.template_name, sibling.claimed_template)
                             IN ('KCC20Sale', 'KCC20SaleV2')
                         AND sibling.claim_verified = TRUE
                   ))
              )
        ),
        owner_sale AS (
            SELECT *
            FROM sale
            WHERE COALESCE(args->>'seller', args->>'listingSeller') ~ '^[0-9a-fA-F]{64}$'
              AND COALESCE(args->>'tokenId', args->>'listingTokenId') ~ '^[0-9a-fA-F]{64}$'
              AND NOT EXISTS (
                  SELECT 1 FROM sale_edges edge
                  WHERE edge.child_covenant_id = sale.covenant_id
              )
        ),
        sale_family(root_covenant_id, covenant_id) AS (
            SELECT covenant_id, covenant_id
            FROM owner_sale
            UNION
            SELECT sf.root_covenant_id, child.covenant_id
            FROM sale_family sf
            JOIN sale_edges edge ON edge.parent_covenant_id = sf.covenant_id
            JOIN covenants child ON child.covenant_id = edge.child_covenant_id
        ),
        sale_spend AS (
            SELECT DISTINCT ON (sf.root_covenant_id)
                sf.root_covenant_id AS covenant_id,
                a.entrypoint,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms
            FROM sale_family sf
            JOIN covenant_actions a
              ON a.covenant_id = sf.covenant_id
             AND a.action = 'spend'
            ORDER BY sf.root_covenant_id, a.block_time_ms DESC, a.id DESC
        ),
        legacy_asks AS (
            SELECT
                encode(s.covenant_id, 'hex') AS order_id,
                'ask'::TEXT AS side,
                CASE
                    WHEN ss.entrypoint IN ('buy', 'buyListing') THEN 'filled'
                    WHEN ss.entrypoint IN ('cancel', 'cancelListing') THEN 'cancelled'
                    WHEN COUNT(DISTINCT su.txid) FILTER (WHERE su.status = 'active') > 0
                     AND COUNT(DISTINCT tu.txid) FILTER (WHERE tu.status = 'active') > 0 THEN 'open'
                    WHEN COUNT(DISTINCT su.txid) FILTER (WHERE su.status = 'active') > 0 THEN 'waitingForLock'
                    ELSE 'closed'
                END AS status,
                COALESCE(s.args->>'tokenId', s.args->>'listingTokenId') AS token_id_hex,
                lower(COALESCE(s.args->>'seller', s.args->>'listingSeller')) AS owner,
                COALESCE(s.args->>'tokenAmount', s.args->>'listingTokenAmount') AS token_amount,
                SUM((COALESCE(tu.state->>'stateAmount', tu.state->>'amount'))::NUMERIC) FILTER (WHERE tu.status = 'active')::TEXT AS remaining_token_amount,
                COALESCE(s.args->>'priceSompi', s.args->>'listingPriceSompi') AS price_sompi,
                NULL::TEXT AS unit_price_sompi,
                NULL::TEXT AS min_fill_amount,
                s.template_name,
                s.address,
                NULL::TEXT AS txid_hex,
                NULL::INT AS vout,
                ss.txid_hex AS close_txid_hex,
                ss.entrypoint AS close_entrypoint,
                s.created_at_ms
            FROM owner_sale s
            LEFT JOIN sale_spend ss ON ss.covenant_id = s.covenant_id
            LEFT JOIN sale_family suf ON suf.root_covenant_id = s.covenant_id
            LEFT JOIN covenant_utxos su ON su.covenant_id = suf.covenant_id
            LEFT JOIN covenant_utxos tu
                   ON tu.covenant_id = decode(COALESCE(s.args->>'tokenId', s.args->>'listingTokenId'), 'hex')
                  AND tu.status = 'active'
                  AND lower(COALESCE(tu.state->>'stateOwner', tu.state->>'ownerIdentifier')) = encode(suf.covenant_id, 'hex')
                  AND (COALESCE(tu.state->>'stateOwnerType', tu.state->>'identifierType'))::INT = 2
                  AND EXISTS (
                      SELECT 1 FROM covenant_utxos active_sale
                      WHERE active_sale.covenant_id = suf.covenant_id
                        AND active_sale.status = 'active'
                  )
            GROUP BY s.covenant_id, s.address, s.template_name, s.args, s.created_at_ms,
                     ss.txid_hex, ss.entrypoint
        ),
        -- Standard orders and fee orders have separate small partial indexes.
        -- Keep the fee fallback disjoint when a fee state also has ownerIdentifier.
        orderbook_utxos AS MATERIALIZED (
            SELECT u.* FROM covenant_utxos u
            WHERE u.status = 'active'
              AND u.state ? 'ownerIdentifier'
              AND u.state ? 'mode'
              AND u.state->>'mode' IN ('2', '3')
            UNION ALL
            SELECT u.* FROM covenant_utxos u
            WHERE u.status = 'active'
              AND NOT (u.state ? 'ownerIdentifier')
              AND u.state->>'feePolicyVersion' = '1'
              AND u.state ? 'feePolicy'
              AND u.state ? 'owner'
              AND u.state ? 'mode'
              AND u.state->>'mode' IN ('2', '3')
        ),
        orderbook_asks AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'ask'::TEXT AS side,
                'open'::TEXT AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex')) AS token_id_hex,
                lower(COALESCE(u.state->>'ownerIdentifier', u.state->>'owner')) AS owner,
                u.state->>'amount' AS token_amount,
                u.state->>'amount' AS remaining_token_amount,
                CASE WHEN (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy') THEN
                    FLOOR((u.state->>'amount')::NUMERIC * (u.state->>'unitPrice')::NUMERIC
                      / GREATEST(COALESCE(NULLIF(u.state->>'priceScale', '')::NUMERIC, 1), 1))::TEXT
                    ELSE ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                END AS price_sompi,
                COALESCE(u.state->>'unitPriceSompi', u.state->>'unitPrice') AS unit_price_sompi,
                u.state->>'minFillAmount' AS min_fill_amount,
                CASE
                    WHEN (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy') THEN
                        CASE u.state->>'mode' WHEN '2' THEN 'KCC20OrderbookFeeAskV1' ELSE 'KCC20OrderbookFeeBidV1' END
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END AS template_name,
                u.address,
                encode(u.txid, 'hex') AS txid_hex,
                u.vout,
                NULL::TEXT AS close_txid_hex,
                NULL::TEXT AS close_entrypoint,
                b.timestamp_ms AS created_at_ms
            FROM orderbook_utxos u
            JOIN covenants c ON c.covenant_id = u.covenant_id
            JOIN blocks b ON b.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
                  OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy')
              )
              AND (u.state ? 'ownerIdentifier' OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'owner'))
              AND u.state ? 'mode'
              AND u.state->>'mode' = '2'
              AND COALESCE(u.state->>'ownerIdentifier', u.state->>'owner') ~ '^[0-9a-fA-F]{64}$'
              AND COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex')) ~ '^[0-9a-fA-F]{64}$'
        ),
        bid_raw AS (
            SELECT
                covenant_id,
                address,
                created_at_ms,
                COALESCE(template_name, claimed_template) AS template_name,
                constructor_args,
                claimed_args
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN ('KCC20BuyOrder')
              AND claim_verified = TRUE
        ),
        bid AS (
            SELECT
                covenant_id,
                address,
                created_at_ms,
                template_name,
                COALESCE(
                    NULLIF(constructor_args, 'null'::jsonb),
                    (
                        SELECT jsonb_object_agg(arg->>'name', arg->'value')
                        FROM jsonb_array_elements(
                            CASE
                                WHEN jsonb_typeof(claimed_args->'args') = 'array' THEN claimed_args->'args'
                                ELSE '[]'::jsonb
                            END
                        ) AS arg
                    )
                ) AS args
            FROM bid_raw
        ),
        owner_bid AS (
            SELECT *
            FROM bid
            WHERE COALESCE(args->>'buyer', args->>'orderBuyer') ~ '^[0-9a-fA-F]{64}$'
              AND COALESCE(args->>'tokenId', args->>'orderedTokenId') ~ '^[0-9a-fA-F]{64}$'
        ),
        bid_spend AS (
            SELECT DISTINCT ON (a.covenant_id)
                a.covenant_id,
                a.entrypoint,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms
            FROM covenant_actions a
            JOIN owner_bid b ON b.covenant_id = a.covenant_id
            WHERE a.action = 'spend'
            ORDER BY a.covenant_id, a.block_time_ms DESC, a.id DESC
        ),
        legacy_bids AS (
            SELECT
                encode(b.covenant_id, 'hex') AS order_id,
                'bid'::TEXT AS side,
                CASE
                    WHEN bs.entrypoint IN ('fillBuyOrder') THEN 'filled'
                    WHEN bs.entrypoint IN ('cancelBuyOrder') THEN 'cancelled'
                    WHEN COUNT(DISTINCT bu.txid) FILTER (WHERE bu.status = 'active') > 0 THEN 'open'
                    ELSE 'closed'
                END AS status,
                COALESCE(b.args->>'tokenId', b.args->>'orderedTokenId') AS token_id_hex,
                lower(COALESCE(b.args->>'buyer', b.args->>'orderBuyer')) AS owner,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS token_amount,
                COALESCE(b.args->>'tokenAmount', b.args->>'orderedTokenAmount') AS remaining_token_amount,
                COALESCE(b.args->>'priceSompi', b.args->>'offerPriceSompi') AS price_sompi,
                NULL::TEXT AS unit_price_sompi,
                NULL::TEXT AS min_fill_amount,
                b.template_name,
                b.address,
                NULL::TEXT AS txid_hex,
                NULL::INT AS vout,
                bs.txid_hex AS close_txid_hex,
                bs.entrypoint AS close_entrypoint,
                b.created_at_ms
            FROM owner_bid b
            LEFT JOIN bid_spend bs ON bs.covenant_id = b.covenant_id
            LEFT JOIN covenant_utxos bu ON bu.covenant_id = b.covenant_id
            GROUP BY b.covenant_id, b.address, b.template_name, b.args, b.created_at_ms,
                     bs.txid_hex, bs.entrypoint
        ),
        orderbook_bids AS (
            SELECT
                encode(u.txid, 'hex') || ':' || u.vout::TEXT AS order_id,
                'bid'::TEXT AS side,
                'open'::TEXT AS status,
                COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex')) AS token_id_hex,
                lower(COALESCE(u.state->>'ownerIdentifier', u.state->>'owner')) AS owner,
                u.state->>'amount' AS token_amount,
                u.state->>'amount' AS remaining_token_amount,
                CASE WHEN (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy') THEN
                    FLOOR((u.state->>'amount')::NUMERIC * (u.state->>'unitPrice')::NUMERIC
                      / GREATEST(COALESCE(NULLIF(u.state->>'priceScale', '')::NUMERIC, 1), 1))::TEXT
                    ELSE ((u.state->>'amount')::NUMERIC * (u.state->>'unitPriceSompi')::NUMERIC)::TEXT
                END AS price_sompi,
                COALESCE(u.state->>'unitPriceSompi', u.state->>'unitPrice') AS unit_price_sompi,
                u.state->>'minFillAmount' AS min_fill_amount,
                CASE
                    WHEN (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy') THEN
                        CASE u.state->>'mode' WHEN '2' THEN 'KCC20OrderbookFeeAskV1' ELSE 'KCC20OrderbookFeeBidV1' END
                    WHEN u.state->>'supplyBacking' = 'kcc20WrapperReserve' THEN 'KCC20Orderbook'
                    ELSE COALESCE(c.template_name, c.claimed_template)
                END AS template_name,
                u.address,
                encode(u.txid, 'hex') AS txid_hex,
                u.vout,
                NULL::TEXT AS close_txid_hex,
                NULL::TEXT AS close_entrypoint,
                blk.timestamp_ms AS created_at_ms
            FROM orderbook_utxos u
            JOIN covenants c ON c.covenant_id = u.covenant_id
            JOIN blocks blk ON blk.hash = u.created_block
            WHERE u.status = 'active'
              AND (
                  COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                  OR u.state->>'supplyBacking' = 'kcc20WrapperReserve'
                  OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'feePolicy')
              )
              AND (u.state ? 'ownerIdentifier' OR (u.state->>'feePolicyVersion' = '1' AND u.state ? 'owner'))
              AND u.state ? 'mode'
              AND u.state->>'mode' = '3'
              AND COALESCE(u.state->>'ownerIdentifier', u.state->>'owner') ~ '^[0-9a-fA-F]{64}$'
              AND COALESCE(NULLIF(u.state->>'canonicalTokenId', ''), encode(u.covenant_id, 'hex')) ~ '^[0-9a-fA-F]{64}$'
        ),
        orders AS (
            SELECT * FROM legacy_asks
            UNION ALL
            SELECT * FROM orderbook_asks
            UNION ALL
            SELECT * FROM legacy_bids
            UNION ALL
            SELECT * FROM orderbook_bids
        )
        INSERT INTO kcc20_owner_orders (
            order_id, side, status, token_id, owner, token_amount,
            remaining_token_amount, price_sompi, unit_price_sompi, min_fill_amount,
            template_name, address, txid, vout, close_txid, close_entrypoint,
            created_at_ms, refreshed_at_ms
        )
        SELECT
            orders.order_id,
            orders.side,
            orders.status,
            decode(orders.token_id_hex, 'hex'),
            orders.owner,
            orders.token_amount,
            orders.remaining_token_amount,
            orders.price_sompi,
            orders.unit_price_sompi,
            orders.min_fill_amount,
            orders.template_name,
            orders.address,
            CASE WHEN orders.txid_hex ~ '^[0-9a-fA-F]{64}$' THEN decode(orders.txid_hex, 'hex') END,
            orders.vout,
            CASE WHEN orders.close_txid_hex ~ '^[0-9a-fA-F]{64}$' THEN decode(orders.close_txid_hex, 'hex') END,
            orders.close_entrypoint,
            orders.created_at_ms,
            freshness.refreshed_at_ms
        FROM orders
        CROSS JOIN freshness
        WHERE orders.owner ~ '^[0-9a-fA-F]{64}$'
          AND orders.token_id_hex ~ '^[0-9a-fA-F]{64}$'
        ON CONFLICT (order_id) DO UPDATE SET
            side = EXCLUDED.side,
            status = EXCLUDED.status,
            token_id = EXCLUDED.token_id,
            owner = EXCLUDED.owner,
            token_amount = EXCLUDED.token_amount,
            remaining_token_amount = EXCLUDED.remaining_token_amount,
            price_sompi = EXCLUDED.price_sompi,
            unit_price_sompi = EXCLUDED.unit_price_sompi,
            min_fill_amount = EXCLUDED.min_fill_amount,
            template_name = EXCLUDED.template_name,
            address = EXCLUDED.address,
            txid = EXCLUDED.txid,
            vout = EXCLUDED.vout,
            close_txid = EXCLUDED.close_txid,
            close_entrypoint = EXCLUDED.close_entrypoint,
            created_at_ms = EXCLUDED.created_at_ms,
            refreshed_at_ms = EXCLUDED.refreshed_at_ms
        "#,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Requires owner orders to have been refreshed through the same dirty pass.
/// The single projector enforces this dependency before calling this function.
pub async fn refresh_kcc20_owner_portfolio_assets(pool: &PgPool) -> Result<()> {
    if !kcc20_owner_portfolio_assets_table_exists(pool).await? {
        anyhow::bail!("kcc20_owner_portfolio_assets migration is required");
    }
    if !kcc20_owner_orders_table_exists(pool).await? {
        anyhow::bail!("kcc20_owner_orders migration is required");
    }
    let started = Instant::now();
    let timeout_secs = std::env::var("TN12_KCC20_OWNER_PORTFOLIO_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(20)
        .clamp(5, 300);
    let statement_timeout = format!("{timeout_secs}s");
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "2s", &statement_timeout).await?;
    // The projection has a high estimated cost but a small indexed working set;
    // per-refresh JIT compilation is substantially slower than execution.
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_owner_portfolio_assets_refresh', 0))",
    )
    .execute(&mut *tx)
    .await?;

    // Readers retain the previous committed snapshot until this transaction commits.
    sqlx::query("DELETE FROM kcc20_owner_portfolio_assets")
        .execute(&mut *tx)
        .await?;
    let inserted = sqlx::query(
        r#"
        WITH RECURSIVE freshness AS (
            SELECT
                (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) AS refreshed_at_ms,
                MAX(blue_score) AS source_blue_score
            FROM blocks
            WHERE is_chain_block
        ),
        claim_descriptors AS (
            SELECT
                c.covenant_id AS token_id,
                NULLIF(COALESCE(args->>'ticker', args->>'symbol'), '') AS ticker,
                NULLIF(COALESCE(args->>'tokenName', args->>'name'), '') AS token_name,
                CASE
                    WHEN args->>'decimals' ~ '^[0-8]$'
                        THEN (args->>'decimals')::SMALLINT
                    WHEN COALESCE(args->>'displayScale', args->>'tokenDisplayScale', args->>'priceScale') ~ '^10{0,8}$'
                        THEN (length(COALESCE(args->>'displayScale', args->>'tokenDisplayScale', args->>'priceScale')) - 1)::SMALLINT
                    ELSE NULL::SMALLINT
                END AS decimals
            FROM covenants c
            LEFT JOIN LATERAL (
                SELECT jsonb_object_agg(arg->>'name', arg->'value') AS claimed
                FROM jsonb_array_elements(
                    CASE
                        WHEN jsonb_typeof(c.claimed_args->'args') = 'array'
                            THEN c.claimed_args->'args'
                        ELSE '[]'::jsonb
                    END
                ) arg
                WHERE jsonb_typeof(arg) = 'object'
                  AND NULLIF(arg->>'name', '') IS NOT NULL
            ) claim ON TRUE
            CROSS JOIN LATERAL (
                SELECT COALESCE(
                           claim.claimed,
                           CASE
                               WHEN jsonb_typeof(c.claimed_args) = 'object'
                                AND COALESCE(jsonb_typeof(c.claimed_args->'args'), 'null') <> 'array'
                               THEN c.claimed_args
                           END,
                           '{}'::jsonb
                       ) || CASE
                           WHEN jsonb_typeof(c.constructor_args) = 'object'
                           THEN jsonb_strip_nulls(c.constructor_args)
                           ELSE '{}'::jsonb
                       END AS args
            ) normalized
            WHERE COALESCE(c.template_name, c.claimed_template) = 'KCC20'
        ),
        wrapper_candidates AS (
            SELECT
                w.*,
                BOOL_OR(w.active_utxos > 0) OVER (
                    PARTITION BY w.canonical_token_id
                ) AS has_active
            FROM kcc20_portfolio_market_identities w
        ),
        accounting_wrappers AS (
            SELECT *
            FROM wrapper_candidates
            WHERE CASE
                WHEN has_active THEN active_utxos > 0
                ELSE TRUE
            END
        ),
        owner_native AS (
            SELECT
                h.owner_identifier,
                h.covenant_id AS canonical_token_id,
                SUM(h.amount_total) AS native_balance,
                SUM(h.utxo_count)::BIGINT AS native_utxo_count,
                MAX(h.last_change_ms) AS native_last_change_ms
            FROM kcc20_holders h
            LEFT JOIN kcc20_portfolio_market_identities w ON w.wrapper_id = h.covenant_id
            WHERE NOT h.is_minter
              AND h.identifier_type <> 4
              AND h.amount_total > 0
              AND w.wrapper_id IS NULL
            GROUP BY h.owner_identifier, h.covenant_id
        ),
        owner_wrapped AS (
            SELECT
                h.owner_identifier,
                w.canonical_token_id,
                SUM(h.amount_total) AS orderbook_balance,
                SUM(h.utxo_count)::BIGINT AS orderbook_utxo_count,
                MAX(h.last_change_ms) AS orderbook_last_change_ms
            FROM kcc20_holders h
            JOIN accounting_wrappers w ON w.wrapper_id = h.covenant_id
            WHERE NOT h.is_minter
              AND h.identifier_type <> 4
              AND h.amount_total > 0
            GROUP BY h.owner_identifier, w.canonical_token_id
        ),
        -- Owner orders were refreshed before this projection in the single
        -- projector pass. Reuse those indexed rows instead of rediscovering
        -- every legacy sale and orderbook UTXO a second time.
        owner_orders AS (
            SELECT
                decode(o.owner, 'hex') AS owner_identifier,
                COALESCE(w.canonical_token_id, o.token_id) AS canonical_token_id,
                COALESCE(SUM(o.remaining_token_amount::NUMERIC)
                    FILTER (WHERE o.side = 'ask'), 0) AS open_ask_amount,
                COALESCE(SUM(o.remaining_token_amount::NUMERIC)
                    FILTER (WHERE o.side = 'bid'), 0) AS open_bid_amount,
                COUNT(*)::BIGINT AS open_order_count,
                MAX(o.created_at_ms) AS order_last_change_ms
            FROM kcc20_owner_orders o
            LEFT JOIN kcc20_portfolio_market_identities any_wrapper
              ON any_wrapper.wrapper_id = o.token_id
            LEFT JOIN accounting_wrappers w ON w.wrapper_id = o.token_id
            WHERE o.status = 'open'
              AND o.owner ~ '^[0-9a-fA-F]{64}$'
              AND o.remaining_token_amount ~ '^[0-9]{1,78}$'
              AND (any_wrapper.wrapper_id IS NULL OR w.wrapper_id IS NOT NULL)
            GROUP BY decode(o.owner, 'hex'), COALESCE(w.canonical_token_id, o.token_id)
        ),
        asset_ids AS (
            SELECT owner_identifier, canonical_token_id FROM owner_native
            UNION
            SELECT owner_identifier, canonical_token_id FROM owner_wrapped
            UNION
            SELECT owner_identifier, canonical_token_id FROM owner_orders
        ),
        asset_token_ids AS (
            SELECT DISTINCT canonical_token_id FROM asset_ids
        ),
        asset_descriptors AS (
            SELECT
                ids.canonical_token_id AS token_id,
                COALESCE(c.ticker, s.ticker) AS ticker,
                COALESCE(c.token_name, s.token_name) AS token_name,
                COALESCE(c.decimals, s.decimals, 0)::SMALLINT AS decimals
            FROM asset_token_ids ids
            LEFT JOIN claim_descriptors c ON c.token_id = ids.canonical_token_id
            LEFT JOIN LATERAL (
                SELECT
                    NULLIF(COALESCE(descriptor.state->>'ticker', descriptor.state->>'symbol'), '') AS ticker,
                    NULLIF(COALESCE(descriptor.state->>'tokenName', descriptor.state->>'name'), '') AS token_name,
                    CASE
                        WHEN descriptor.state->>'decimals' ~ '^[0-8]$'
                            THEN (descriptor.state->>'decimals')::SMALLINT
                        WHEN COALESCE(descriptor.state->>'displayScale', descriptor.state->>'priceScale', descriptor.state->>'tokenDisplayScale') ~ '^10{0,8}$'
                            THEN (length(COALESCE(descriptor.state->>'displayScale', descriptor.state->>'priceScale', descriptor.state->>'tokenDisplayScale')) - 1)::SMALLINT
                        ELSE NULL::SMALLINT
                    END AS decimals
                FROM covenant_utxos u
                CROSS JOIN LATERAL (
                    -- Standard KCC20 stores display identity in its decoded extension.
                    -- Keep explicit legacy top-level fields authoritative when present.
                    SELECT CASE WHEN jsonb_typeof(u.state->'extension') = 'object'
                                THEN u.state->'extension' ELSE '{}'::jsonb END
                           || jsonb_strip_nulls(u.state) AS state
                ) descriptor
                LEFT JOIN blocks b ON b.hash = u.created_block
                WHERE u.covenant_id = ids.canonical_token_id
                  AND (c.ticker IS NULL OR c.token_name IS NULL OR c.decimals IS NULL)
                  AND (
                      descriptor.state ? 'ticker'
                      OR descriptor.state ? 'tokenName'
                      OR descriptor.state ? 'name'
                      OR descriptor.state ? 'decimals'
                      OR descriptor.state ? 'displayScale'
                      OR descriptor.state ? 'priceScale'
                      OR descriptor.state ? 'tokenDisplayScale'
                  )
                ORDER BY (u.status = 'active') DESC,
                         b.timestamp_ms DESC NULLS LAST,
                         u.txid DESC,
                         u.vout DESC
                LIMIT 1
            ) s ON TRUE
        ),
        current_wrappers AS (
            SELECT DISTINCT ON (canonical_token_id)
                canonical_token_id,
                wrapper_id,
                fee_ticket_id
            FROM accounting_wrappers
            ORDER BY canonical_token_id,
                     active_utxos DESC,
                     pending_reveal ASC,
                     wrapper_id ASC
        ),
        market_token_ids AS (
            SELECT
                canonical_token_id,
                canonical_token_id AS market_token_id
            FROM asset_token_ids

            UNION

            SELECT
                ids.canonical_token_id,
                wrapper.wrapper_id AS market_token_id
            FROM asset_token_ids ids
            JOIN accounting_wrappers wrapper
              ON wrapper.canonical_token_id = ids.canonical_token_id
        ),
        market_prices AS (
            SELECT
                market.canonical_token_id,
                MIN(summary.best_ask_unit_price_sompi) AS best_ask_unit_price_sompi,
                MAX(summary.best_bid_unit_price_sompi) AS best_bid_unit_price_sompi
            FROM market_token_ids market
            JOIN kcc20_market_summaries summary
              ON summary.token_id = market.market_token_id
            GROUP BY market.canonical_token_id
        )
        INSERT INTO kcc20_owner_portfolio_assets (
            owner_identifier, canonical_token_id, wrapper_id, wrapped_market_id,
            native_balance, orderbook_balance, total_balance, asset_utxo_count,
            open_ask_amount, open_bid_amount, open_order_count,
            best_ask_unit_price_sompi, best_bid_unit_price_sompi, value_sompi,
            fee_ticket_supported, last_change_ms, ticker, token_name, decimals,
            refreshed_at_ms, source_blue_score
        )
        SELECT
            ids.owner_identifier,
            ids.canonical_token_id,
            cw.wrapper_id,
            cw.wrapper_id,
            COALESCE(native.native_balance, 0),
            COALESCE(orderbook.orderbook_balance, 0),
            COALESCE(native.native_balance, 0) + COALESCE(orderbook.orderbook_balance, 0),
            COALESCE(native.native_utxo_count, 0) + COALESCE(orderbook.orderbook_utxo_count, 0),
            COALESCE(o.open_ask_amount, 0),
            COALESCE(o.open_bid_amount, 0),
            COALESCE(o.open_order_count, 0),
            m.best_ask_unit_price_sompi,
            m.best_bid_unit_price_sompi,
            CASE
                WHEN m.best_ask_unit_price_sompi IS NULL THEN NULL
                ELSE trunc(
                    (COALESCE(native.native_balance, 0) + COALESCE(orderbook.orderbook_balance, 0))
                    * m.best_ask_unit_price_sompi
                    / power(10::NUMERIC, COALESCE(d.decimals, 0))
                )
            END,
            cw.fee_ticket_id IS NOT NULL
              AND cw.fee_ticket_id <> decode(repeat('00', 32), 'hex'),
            GREATEST(
                COALESCE(native.native_last_change_ms, 0),
                COALESCE(orderbook.orderbook_last_change_ms, 0),
                COALESCE(o.order_last_change_ms, 0)
            ),
            d.ticker,
            d.token_name,
            COALESCE(d.decimals, 0),
            f.refreshed_at_ms,
            f.source_blue_score
        FROM asset_ids ids
        CROSS JOIN freshness f
        LEFT JOIN owner_native native
          ON native.owner_identifier = ids.owner_identifier
         AND native.canonical_token_id = ids.canonical_token_id
        LEFT JOIN owner_wrapped orderbook
          ON orderbook.owner_identifier = ids.owner_identifier
         AND orderbook.canonical_token_id = ids.canonical_token_id
        LEFT JOIN owner_orders o
          ON o.owner_identifier = ids.owner_identifier
         AND o.canonical_token_id = ids.canonical_token_id
        LEFT JOIN current_wrappers cw ON cw.canonical_token_id = ids.canonical_token_id
        LEFT JOIN market_prices m ON m.canonical_token_id = ids.canonical_token_id
        LEFT JOIN asset_descriptors d ON d.token_id = ids.canonical_token_id
        "#,
    )
    .execute(&mut *tx)
    .await?;
    let inserted_rows = inserted.rows_affected();
    tx.commit().await?;
    tracing::info!(
        target: "kcc20_projector",
        projection = KCC20_OWNER_PORTFOLIO_ASSETS_PROJECTION,
        inserted_rows,
        elapsed_ms = started.elapsed().as_millis(),
        timeout_secs,
        "refreshed KCC20 owner portfolio assets"
    );
    Ok(())
}

pub async fn refresh_kcc20_activity_feed(pool: &PgPool) -> Result<()> {
    refresh_kcc20_activity_feed_with_config(pool, Kcc20ActivityFeedRefreshConfig::request_path())
        .await?;
    Ok(())
}

pub async fn refresh_kcc20_activity_feed_with_config(
    pool: &PgPool,
    config: Kcc20ActivityFeedRefreshConfig,
) -> Result<Kcc20ActivityFeedRefreshStats> {
    let started = Instant::now();
    let mut tx = pool.begin().await?;
    set_local_query_limits(&mut tx, "2s", &config.statement_timeout).await?;
    // A retained dirty queue can inflate the scoped query's estimated cost.
    // Compiling its expressions takes seconds even for a few indexed actions.
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    if config.wait_for_lock {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_activity_feed_refresh', 0))",
        )
        .execute(&mut *tx)
        .await?;
    } else {
        let lock_acquired: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended('tn12:kcc20_activity_feed_refresh', 0))",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !lock_acquired {
            tracing::debug!("skipping overlapping KCC20 activity feed refresh");
            tx.rollback().await?;
            return Ok(Kcc20ActivityFeedRefreshStats {
                target_dirty_id: 0,
                last_dirty_id: 0,
                dirty_rows: 0,
                activity_dirty_rows: 0,
                scoped_dirty_txids: 0,
                mode: Kcc20ActivityFeedRefreshMode::SkippedLock,
                refresh_from_ms: 0,
                rows_deleted: 0,
                rows_inserted: 0,
                elapsed_ms: started.elapsed().as_millis() as u64,
            });
        }
    }

    let target_dirty_id: i64 = match config.target_dirty_id {
        Some(value) => value,
        None => {
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
                .fetch_one(&mut *tx)
                .await?
        }
    };
    let summary = sqlx::query(
        r#"
        WITH feed AS (
            SELECT MAX(block_time_ms) AS max_block_time_ms
            FROM kcc20_activity_feed
        ),
        state AS (
            SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
            FROM kcc20_projection_state
            WHERE name = 'activity_feed'
        ),
        pending_dirty AS (
            SELECT dirty.reason, dirty.txid
            FROM kcc20_projection_dirty dirty
            WHERE dirty.id > COALESCE((SELECT last_dirty_id FROM state), 0)
              AND dirty.id <= $2::BIGINT
        ),
        pending_bounds AS (
            SELECT
                COALESCE((SELECT last_dirty_id FROM state), 0)::BIGINT AS last_dirty_id,
                COUNT(*)::BIGINT AS dirty_rows,
                COUNT(*) FILTER (
                    WHERE pending_dirty.txid IS NOT NULL
                       OR pending_dirty.reason = 'activity_feed_dirty_txid_backfill'
                       OR (
                            pending_dirty.txid IS NULL
                            AND pending_dirty.reason NOT IN (
                                'activity_feed_dirty_txid_backfill',
                                'block_revert_legacy_repair',
                                'periodic_projection_repair',
                                'owner_orders_projection_added',
                                'owner_portfolio_assets_projection_added'
                            )
                       )
                )::BIGINT AS activity_dirty_rows,
                COUNT(DISTINCT pending_dirty.txid)
                    FILTER (WHERE pending_dirty.txid IS NOT NULL)::BIGINT AS scoped_dirty_txids,
                COALESCE(BOOL_OR(
                    pending_dirty.txid IS NULL
                    AND pending_dirty.reason NOT IN (
                        'activity_feed_dirty_txid_backfill',
                        'block_revert_legacy_repair',
                        'periodic_projection_repair',
                        'owner_orders_projection_added',
                        'owner_portfolio_assets_projection_added'
                    )
                ), FALSE) AS has_unscoped_dirty
            FROM pending_dirty
        )
        SELECT
            pending_bounds.last_dirty_id,
            pending_bounds.dirty_rows,
            pending_bounds.activity_dirty_rows,
            pending_bounds.scoped_dirty_txids,
            pending_bounds.has_unscoped_dirty,
            feed.max_block_time_ms,
            CASE
                WHEN feed.max_block_time_ms IS NULL
                    THEN 0
                WHEN pending_bounds.has_unscoped_dirty
                    THEN 0
                ELSE GREATEST(feed.max_block_time_ms - $1::BIGINT, 0)
            END AS refresh_from_ms
        FROM feed
        CROSS JOIN pending_bounds
        "#,
    )
    .bind(KCC20_ACTIVITY_REFRESH_OVERLAP_MS)
    .bind(target_dirty_id)
    .fetch_one(&mut *tx)
    .await?;

    let last_dirty_id: i64 = summary.get("last_dirty_id");
    let dirty_rows: i64 = summary.get("dirty_rows");
    let activity_dirty_rows: i64 = summary.get("activity_dirty_rows");
    let scoped_dirty_txids: i64 = summary.get("scoped_dirty_txids");
    let has_unscoped_dirty: bool = summary.get("has_unscoped_dirty");
    let feed_max_block_time_ms: Option<i64> = summary.get("max_block_time_ms");
    let refresh_from_ms: i64 = summary.get("refresh_from_ms");
    if dirty_rows == 0 {
        tx.rollback().await?;
        return Ok(Kcc20ActivityFeedRefreshStats {
            target_dirty_id,
            last_dirty_id,
            dirty_rows,
            activity_dirty_rows,
            scoped_dirty_txids,
            mode: Kcc20ActivityFeedRefreshMode::Clean,
            refresh_from_ms,
            rows_deleted: 0,
            rows_inserted: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }
    if activity_dirty_rows == 0 {
        sqlx::query(
            r#"
            INSERT INTO kcc20_projection_state (name, last_dirty_id, refreshed_at_ms)
            VALUES ($1, $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
            ON CONFLICT (name) DO UPDATE SET
                last_dirty_id = GREATEST(kcc20_projection_state.last_dirty_id, EXCLUDED.last_dirty_id),
                refreshed_at_ms = EXCLUDED.refreshed_at_ms
            "#,
        )
        .bind(KCC20_ACTIVITY_FEED_PROJECTION)
        .bind(target_dirty_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Kcc20ActivityFeedRefreshStats {
            target_dirty_id,
            last_dirty_id,
            dirty_rows,
            activity_dirty_rows,
            scoped_dirty_txids,
            mode: Kcc20ActivityFeedRefreshMode::SkippedIrrelevant,
            refresh_from_ms,
            rows_deleted: 0,
            rows_inserted: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    let full_refresh_required = feed_max_block_time_ms.is_none() || has_unscoped_dirty;
    if full_refresh_required && !config.full_refresh_enabled {
        tx.rollback().await?;
        return Ok(Kcc20ActivityFeedRefreshStats {
            target_dirty_id,
            last_dirty_id,
            dirty_rows,
            activity_dirty_rows,
            scoped_dirty_txids,
            mode: Kcc20ActivityFeedRefreshMode::DisabledFull,
            refresh_from_ms,
            rows_deleted: 0,
            rows_inserted: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }
    let scoped_only = !full_refresh_required && scoped_dirty_txids > 0;
    let mode = if full_refresh_required {
        Kcc20ActivityFeedRefreshMode::Full
    } else if scoped_only {
        Kcc20ActivityFeedRefreshMode::ScopedTxids
    } else {
        Kcc20ActivityFeedRefreshMode::RecentWindow
    };

    let deleted = if scoped_only {
        sqlx::query(
            r#"
            WITH state AS (
                SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
                FROM kcc20_projection_state
                WHERE name = 'activity_feed'
            ),
            pending_dirty AS (
                SELECT DISTINCT dirty.txid
                FROM kcc20_projection_dirty dirty
                WHERE dirty.id > COALESCE((SELECT last_dirty_id FROM state), 0)
                  AND dirty.id <= $1::BIGINT
                  AND dirty.txid IS NOT NULL
            )
            DELETE FROM kcc20_activity_feed feed
            USING pending_dirty dirty
            WHERE dirty.txid = feed.txid
            "#,
        )
        .bind(target_dirty_id)
        .execute(&mut *tx)
        .await?
    } else {
        sqlx::query(
            r#"
            WITH state AS (
                SELECT COALESCE(last_dirty_id, 0)::BIGINT AS last_dirty_id
                FROM kcc20_projection_state
                WHERE name = 'activity_feed'
            ),
            pending_dirty AS (
                SELECT DISTINCT dirty.txid
                FROM kcc20_projection_dirty dirty
                WHERE dirty.id > COALESCE((SELECT last_dirty_id FROM state), 0)
                  AND dirty.id <= $2::BIGINT
                  AND dirty.txid IS NOT NULL
            )
            DELETE FROM kcc20_activity_feed feed
            WHERE feed.block_time_ms >= $1
               OR EXISTS (
                    SELECT 1
                    FROM pending_dirty dirty
                    WHERE dirty.txid = feed.txid
               )
            "#,
        )
        .bind(refresh_from_ms)
        .bind(target_dirty_id)
        .execute(&mut *tx)
        .await?
    };
    let inserted_sql = kcc20_activity_refresh_sql(
        r#"
        INSERT INTO kcc20_activity_feed (
            event_id, token_id, txid, block_time_ms, entrypoint, kind, side, order_id,
            owner_identifier, owner_identifier_type,
            owner_identifier_type_version, token_amount, unit_price_sompi,
            price_sompi
        )
        WITH pending_dirty AS (
            SELECT DISTINCT dirty.txid
            FROM kcc20_projection_dirty dirty
            WHERE dirty.id > COALESCE((
                SELECT state.last_dirty_id
                FROM kcc20_projection_state state
                WHERE state.name = 'activity_feed'
            ), 0)
              AND dirty.id <= $2::BIGINT
              AND dirty.txid IS NOT NULL
        ),
        activity AS (
            SELECT
                kcc20_activity_event_id(a.txid, a.action, a.inputs, a.outputs) AS event_id,
                COALESCE(
                    encode(a.canonical_token_id, 'hex'),
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(order_out.outputs->'state'->>'canonicalTokenId', ''),
                    NULLIF(a.decoded_args->>'utilityTokenId', ''),
                    NULLIF(order_out.outputs->'state'->>'utilityTokenId', ''),
                    NULLIF(holder_out.outputs->'state'->>'utilityTokenId', ''),
                    NULLIF(holder_out.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                a.txid,
                a.block_time_ms,
                COALESCE(a.entrypoint, parent_spend.entrypoint) AS entrypoint,
                CASE
                    WHEN a.action = 'deploy' THEN 'deploy'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('createAskByOwnerSig') THEN 'orderCreated'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('createBidFromRoot') THEN 'orderCreated'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig') THEN 'orderCancelled'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide') THEN 'trade'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'mergeByOwnerSig' THEN 'consolidate'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('mint_by_owner', 'mint_public') THEN 'mint'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'set_public_mint_active' THEN 'mintConfig'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('transfer', 'transfer_delegator') THEN 'transfer'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'burnByOwnerSig'
                     AND COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket' THEN 'feeTicketBurn'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'burn' THEN 'burn'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'wrap' THEN 'wrap'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('unwrap', 'unwrapByOwnerSig') THEN 'unwrap'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'createFromUtilityBurn' THEN 'feeTicketCreate'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'updateDenominationByOwnerSig' THEN 'feeTicketConfig'
                    ELSE 'action'
                END AS kind,
                CASE
                    WHEN a.entrypoint IN ('createAskByOwnerSig', 'fillAskPartial', 'crossAskSide', 'cancelAskByOwnerSig') THEN 'ask'
                    WHEN a.entrypoint IN ('createBidFromRoot', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossBidSide', 'cancelBidByOwnerSig') THEN 'bid'
                    ELSE NULL
                END AS side,
                CASE
                    WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                     AND a.inputs->'previousOutpoint'->>'hash' IS NOT NULL
                        THEN (a.inputs->'previousOutpoint'->>'hash') || ':' || (a.inputs->'previousOutpoint'->>'index')
                    WHEN order_out.outputs->>'vout' IS NOT NULL THEN encode(a.txid, 'hex') || ':' || (order_out.outputs->>'vout')
                    WHEN a.inputs->'previousOutpoint'->>'hash' IS NOT NULL THEN (a.inputs->'previousOutpoint'->>'hash') || ':' || (a.inputs->'previousOutpoint'->>'index')
                    ELSE NULL
                END AS order_id,
                CASE
                    WHEN a.entrypoint = 'wrap' THEN COALESCE(
                        NULLIF(a.decoded_args->>'wrappedRecipient', ''),
                        lifecycle_out.owner_identifier,
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner'
                    )
                    WHEN a.entrypoint = 'unwrap' THEN COALESCE(
                        NULLIF(a.decoded_args->>'tokenRecipient', ''),
                        lifecycle_out.owner_identifier,
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner',
                        holder_out.outputs->'state'->>'ownerIdentifier'
                    )
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide') THEN COALESCE(
                        NULLIF(seller_spend.decoded_args->>'ownerIdentifier', ''),
                        NULLIF(a.decoded_args->>'seller', ''),
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier'
                    )
                    ELSE COALESCE(
                        holder_out.outputs->'state'->>'owner',
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        order_out.outputs->'state'->>'ownerIdentifier',
                        a.outputs->'state'->>'owner',
                        a.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner',
                        a.decoded_args->>'owner',
                        a.decoded_args->>'seller',
                        a.decoded_args->>'buyer',
                        a.decoded_args->>'ticketOwner',
                        a.decoded_args->>'toOwner',
                        a.decoded_args->>'tokenRecipient'
                    )
                END AS owner_identifier,
                CASE
                    WHEN a.entrypoint = 'wrap' THEN CASE
                        WHEN NULLIF(a.decoded_args->>'wrappedRecipient', '') IS NOT NULL
                            THEN 0::SMALLINT
                        WHEN lifecycle_out.owner_identifier IS NOT NULL THEN CASE
                            WHEN lifecycle_out.owner_identifier_type ~ '^[012]$'
                                THEN lifecycle_out.owner_identifier_type::SMALLINT
                            ELSE NULL
                        END
                        WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                                THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (a.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                                THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                            ELSE NULL
                        END
                        ELSE NULL
                    END
                    WHEN a.entrypoint = 'unwrap' THEN CASE
                        WHEN NULLIF(a.decoded_args->>'tokenRecipient', '') IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'tokenRecipientScheme' ~ '^[012]$'
                                THEN (a.decoded_args->>'tokenRecipientScheme')::SMALLINT
                            ELSE NULL
                        END
                        WHEN lifecycle_out.owner_identifier IS NOT NULL THEN CASE
                            WHEN lifecycle_out.owner_identifier_type ~ '^[012]$'
                                THEN lifecycle_out.owner_identifier_type::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (a.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                                THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                                THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        ELSE NULL
                    END
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide')
                     AND (
                        NULLIF(seller_spend.decoded_args->>'ownerIdentifier', '') IS NOT NULL
                        OR NULLIF(a.decoded_args->>'seller', '') IS NOT NULL
                     ) THEN COALESCE(
                        CASE
                            WHEN seller_spend.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (seller_spend.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END,
                        0::SMALLINT
                    )
                    WHEN holder_out.outputs->'state'->>'owner' IS NOT NULL THEN CASE
                        WHEN holder_out.outputs->'state'->>'ownerScheme' ~ '^[0-4]$'
                            THEN (holder_out.outputs->'state'->>'ownerScheme')::SMALLINT
                        ELSE NULL
                    END
                    WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN order_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN order_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (order_out.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.outputs->'state'->>'owner' IS NOT NULL THEN CASE
                        WHEN a.outputs->'state'->>'ownerScheme' ~ '^[0-4]$'
                            THEN (a.outputs->'state'->>'ownerScheme')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN a.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (a.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                            THEN (a.decoded_args->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                            THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                        ELSE NULL
                    END
                    -- These legacy fields are fixed 32-byte x-only public keys
                    -- in their decoder schemas and have no sibling type field.
                    WHEN a.decoded_args->>'owner' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'seller' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'buyer' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'ticketOwner' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'toOwner' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'toOwnerType' ~ '^[012]$'
                            THEN (a.decoded_args->>'toOwnerType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'tokenRecipient' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'tokenRecipientScheme' ~ '^[012]$'
                            THEN (a.decoded_args->>'tokenRecipientScheme')::SMALLINT
                        ELSE NULL
                    END
                    ELSE NULL
                END AS owner_identifier_type,
                activity_values.token_amount,
                activity_values.unit_price_sompi,
                CASE
                    WHEN activity_values.token_amount ~ '^[0-9]+$'
                     AND activity_values.unit_price_sompi ~ '^[0-9]+$'
                    THEN FLOOR(
                        activity_values.token_amount::NUMERIC
                        * activity_values.unit_price_sompi::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder_out.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(order_out.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            __KCC20_ACTIVITY_REFRESH_SCOPE_JOIN__
            JOIN covenants c ON c.covenant_id = a.covenant_id
            LEFT JOIN LATERAL (
                SELECT spend.entrypoint
                FROM covenant_actions spend
                JOIN covenants spend_c ON spend_c.covenant_id = spend.covenant_id
                WHERE spend.txid = a.txid
                  AND spend.action = 'spend'
                  AND spend.entrypoint IS NOT NULL
                  AND (
                    spend.covenant_id = a.covenant_id
                    OR (
                        COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                        AND COALESCE(spend_c.template_name, spend_c.claimed_template) = 'KCC20'
                        AND COALESCE(spend.canonical_token_id, spend.covenant_id)
                            = COALESCE(a.canonical_token_id, a.covenant_id)
                    )
                  )
                ORDER BY
                  CASE
                    WHEN a.action = 'continuation'
                     AND a.outputs->>'vout' IN (
                       spend.decoded_args->>'tokenOutputIndex',
                       spend.decoded_args->>'changeOutputIndex',
                       spend.decoded_args->>'minterOutputIndex',
                       spend.decoded_args->>'mergedOutputIndex'
                     ) THEN 0
                    WHEN NOT (
                       spend.decoded_args ? 'tokenOutputIndex'
                       OR spend.decoded_args ? 'changeOutputIndex'
                       OR spend.decoded_args ? 'minterOutputIndex'
                       OR spend.decoded_args ? 'mergedOutputIndex'
                    ) THEN 1
                    ELSE 2
                  END,
                  CASE WHEN spend.covenant_id = a.covenant_id THEN 0 ELSE 1 END,
                  spend.id ASC
                LIMIT 1
            ) parent_spend ON TRUE
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions cont
                WHERE cont.covenant_id = a.covenant_id
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->'state'->>'mode' IN ('2', '3')
                  AND (
                      COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) IS NULL
                      OR cont.outputs->>'vout' = COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', ''))
                  )
                ORDER BY
                  CASE
                      WHEN COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) IS NOT NULL
                       AND cont.outputs->>'vout' = COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) THEN 0
                      ELSE 1
                  END,
                  (cont.outputs ? 'vout') DESC,
                  cont.id DESC
                LIMIT 1
            ) order_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions cont
                WHERE cont.covenant_id = a.covenant_id
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR cont.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND cont.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (cont.outputs ? 'vout') DESC,
                  cont.id DESC
                LIMIT 1
            ) holder_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT
                    cont.outputs->'state'->>'ownerIdentifier' AS owner_identifier,
                    cont.outputs->'state'->>'identifierType' AS owner_identifier_type
                FROM covenant_actions cont
                WHERE a.entrypoint IN ('wrap', 'unwrap')
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->>'vout' = CASE
                      WHEN a.entrypoint = 'wrap'
                          THEN a.decoded_args->>'orderbookHolderOutputIndex'
                      WHEN a.entrypoint = 'unwrap'
                          THEN a.decoded_args->>'tokenRecipientOutputIndex'
                      ELSE NULL
                  END
                  AND lower(COALESCE(
                        encode(cont.canonical_token_id, 'hex'),
                        NULLIF(cont.outputs->'state'->>'canonicalTokenId', ''),
                        encode(cont.covenant_id, 'hex')
                      )) = lower(COALESCE(
                        encode(a.canonical_token_id, 'hex'),
                        NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                        encode(a.covenant_id, 'hex')
                      ))
                ORDER BY cont.id DESC
                LIMIT 1
            ) lifecycle_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT decoded_args
                FROM covenant_actions seller_spend
                WHERE seller_spend.covenant_id = a.covenant_id
                  AND seller_spend.txid = a.txid
                  AND seller_spend.action = 'spend'
                  AND NULLIF(a.decoded_args->>'sellerInputIndex', '') IS NOT NULL
                  AND seller_spend.decoded_args->>'inputIndex' = a.decoded_args->>'sellerInputIndex'
                ORDER BY seller_spend.id ASC
                LIMIT 1
            ) seller_spend ON TRUE
            CROSS JOIN LATERAL (
                SELECT
                    CASE
                        WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                            THEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder_out.outputs->'state'->>'amount')
                        WHEN a.entrypoint IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig')
                            THEN a.decoded_args->>'amount'
                        WHEN a.entrypoint = 'wrap'
                            THEN NULLIF(a.decoded_args->>'tokenAmount', '')
                        WHEN a.entrypoint = 'unwrap'
                            THEN NULLIF(a.decoded_args->>'tokenAmount', '')
                        WHEN a.entrypoint = 'unwrapByOwnerSig'
                            THEN COALESCE(
                                NULLIF(a.decoded_args->>'tokenAmount', ''),
                                NULLIF(a.decoded_args->>'amount', ''),
                                NULLIF(a.decoded_args->>'stateAmount', '')
                            )
                        WHEN a.entrypoint = 'burn'
                            THEN NULLIF(a.decoded_args->>'burnAmount', '')
                        ELSE COALESCE(
                            order_out.outputs->'state'->>'amount',
                            holder_out.outputs->'state'->>'amount',
                            a.outputs->'state'->>'amount',
                            a.decoded_args->>'amount',
                            a.decoded_args->>'tokenAmount',
                            a.decoded_args->>'denomination',
                            a.outputs->'state'->>'denomination'
                        )
                    END AS token_amount,
                    CASE
                        WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                            THEN a.decoded_args->>'unitPriceSompi'
                        WHEN a.entrypoint IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig')
                            THEN a.decoded_args->>'unitPriceSompi'
                        ELSE COALESCE(order_out.outputs->'state'->>'unitPriceSompi', a.decoded_args->>'unitPriceSompi')
                    END AS unit_price_sompi
            ) activity_values
            WHERE __KCC20_ACTIVITY_REFRESH_SCOPE_FILTER__
              AND (
                COALESCE(c.template_name, c.claimed_template) IN ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')
                OR (
                    a.canonical_token_id IS NOT NULL
                    AND a.action IN ('deploy', 'continuation')
                    AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                    AND a.outputs->'state' ? 'ticker'
                    AND a.outputs->'state' ? 'tokenName'
                )
              )
              AND (
                (
                    (
                        COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                        OR (
                            a.canonical_token_id IS NOT NULL
                            AND a.action IN ('deploy', 'continuation')
                            AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                            AND a.outputs->'state' ? 'ticker'
                            AND a.outputs->'state' ? 'tokenName'
                        )
                    )
                    AND (
                        a.action = 'deploy'
                        OR (
                            a.action = 'continuation'
                            AND COALESCE(parent_spend.entrypoint, '') <> 'burn'
                        )
                        OR (a.action = 'spend' AND a.entrypoint = 'burn')
                    )
                )
                OR (
                    a.action = 'spend'
                    AND (
                        (
                            COALESCE(c.template_name, c.claimed_template) IN ('KCC20Orderbook', 'KCC20Wrapper')
                            AND a.entrypoint IN (
                                'createAskByOwnerSig', 'createBidFromRoot',
                                'fillAskPartial', 'fillBidPartial',
                                'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig',
                                'crossAskSide', 'crossBidSide',
                                'cancelAskByOwnerSig', 'cancelBidByOwnerSig',
                                'unwrapByOwnerSig', 'mergeByOwnerSig'
                            )
                        )
                        OR (
                            (c.template_name = 'KCC20Wrapper'
                             OR c.claimed_template = 'KCC20Wrapper')
                            AND a.entrypoint IN ('wrap', 'unwrap')
                        )
                        OR (
                            COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                            AND a.entrypoint IN (
                                'createFromUtilityBurn',
                                'transferByOwnerSig',
                                'burnByOwnerSig',
                                'updateDenominationByOwnerSig'
                            )
                        )
                    )
                )
              )
              AND NOT (
                a.action = 'spend'
                AND a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                  )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__
              -- A spend outpoint can occur only once in an accepted
              -- transaction. Historical canonicalization occasionally
              -- projected that same wrapper input under two covenant ids;
              -- retain the newest source row without collapsing genuinely
              -- batched lifecycle inputs, whose previous outpoints differ.
              AND NOT (
                a.action = 'spend'
                AND a.entrypoint IN ('wrap', 'unwrap')
                AND a.inputs->'previousOutpoint'->>'hash' IS NOT NULL
                AND a.inputs->'previousOutpoint'->>'index' IS NOT NULL
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions duplicate_lifecycle
                  JOIN covenants duplicate_c
                    ON duplicate_c.covenant_id = duplicate_lifecycle.covenant_id
                  WHERE duplicate_lifecycle.txid = a.txid
                    AND duplicate_lifecycle.action = 'spend'
                    AND duplicate_lifecycle.entrypoint = a.entrypoint
                    AND duplicate_lifecycle.id > a.id
                    AND lower(duplicate_lifecycle.inputs->'previousOutpoint'->>'hash')
                        = lower(a.inputs->'previousOutpoint'->>'hash')
                    AND duplicate_lifecycle.inputs->'previousOutpoint'->>'index'
                        = a.inputs->'previousOutpoint'->>'index'
                    AND COALESCE(
                          duplicate_c.template_name,
                          duplicate_c.claimed_template
                        ) = 'KCC20Wrapper'
                    AND lower(COALESCE(
                          encode(duplicate_lifecycle.canonical_token_id, 'hex'),
                          NULLIF(
                            duplicate_lifecycle.decoded_args->>'canonicalTokenId',
                            ''
                          ),
                          encode(duplicate_lifecycle.covenant_id, 'hex')
                        )) = lower(COALESCE(
                          encode(a.canonical_token_id, 'hex'),
                          NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                          encode(a.covenant_id, 'hex')
                        ))
                )
              )
              AND NOT (
                COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('mint_by_owner', 'mint_public')
                AND a.action = 'continuation'
                AND COALESCE(
                    a.outputs->'state'->>'isMintAuthority',
                    a.outputs->'state'->>'isMinter',
                    'false'
                ) = 'true'
              )
              AND NOT (
                (
                    (
                        a.action = 'continuation'
                        AND (
                            COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                            OR (
                                a.canonical_token_id IS NOT NULL
                                AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                                AND a.outputs->'state' ? 'ticker'
                                AND a.outputs->'state' ? 'tokenName'
                            )
                        )
                    )
                    OR (
                        a.action = 'spend'
                        AND COALESCE(c.template_name, c.claimed_template) IN (
                          'KCC20Orderbook', 'KCC20Wrapper'
                        )
                        AND a.entrypoint = 'unwrapByOwnerSig'
                    )
                )
                AND EXISTS (
                    SELECT 1
                    FROM covenant_actions wrapper_action
                    JOIN covenants wrapper_c
                      ON wrapper_c.covenant_id = wrapper_action.covenant_id
                    WHERE wrapper_action.txid = a.txid
                      AND wrapper_action.action = 'spend'
                      AND wrapper_action.entrypoint IN ('wrap', 'unwrap')
                      AND (wrapper_c.template_name = 'KCC20Wrapper'
                           OR wrapper_c.claimed_template = 'KCC20Wrapper')
                      AND lower(COALESCE(
                            encode(wrapper_action.canonical_token_id, 'hex'),
                            NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                          )) = lower(COALESCE(
                            encode(a.canonical_token_id, 'hex'),
                            NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                            NULLIF(order_out.outputs->'state'->>'canonicalTokenId', ''),
                            NULLIF(a.decoded_args->>'utilityTokenId', ''),
                            NULLIF(order_out.outputs->'state'->>'utilityTokenId', ''),
                            NULLIF(holder_out.outputs->'state'->>'utilityTokenId', ''),
                            NULLIF(holder_out.outputs->'state'->>'canonicalTokenId', ''),
                            encode(a.covenant_id, 'hex')
                          ))
                      AND (
                        (
                          a.action = 'spend'
                          AND (
                            (
                              wrapper_action.covenant_id = a.covenant_id
                              AND wrapper_action.decoded_args->>'wrappedInputIndex' IS NOT NULL
                              AND a.decoded_args->>'inputIndex' = wrapper_action.decoded_args->>'wrappedInputIndex'
                            )
                            OR (
                              wrapper_action.covenant_id = a.covenant_id
                              AND
                              wrapper_action.decoded_args->>'wrappedInputIndex' IS NULL
                              AND 1 = (
                                SELECT COUNT(*)
                                FROM covenant_actions wrapped_spend
                                WHERE wrapped_spend.txid = a.txid
                                  AND wrapped_spend.action = 'spend'
                                  AND wrapped_spend.entrypoint = 'unwrapByOwnerSig'
                                  AND lower(COALESCE(
                                        encode(wrapped_spend.canonical_token_id, 'hex'),
                                        NULLIF(wrapped_spend.decoded_args->>'canonicalTokenId', '')
                                      )) = lower(COALESCE(
                                        encode(wrapper_action.canonical_token_id, 'hex'),
                                        NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                      ))
                              )
                            )
                          )
                        )
                        OR (
                          a.action = 'continuation'
                          AND (
                            EXISTS (
                              SELECT 1
                              FROM covenant_actions token_spend
                              JOIN covenants token_c
                                ON token_c.covenant_id = token_spend.covenant_id
                              WHERE token_spend.txid = a.txid
                                AND token_spend.action = 'spend'
                                AND COALESCE(token_c.template_name, token_c.claimed_template) = 'KCC20'
                                AND lower(COALESCE(
                                      encode(token_spend.canonical_token_id, 'hex'),
                                      encode(token_spend.covenant_id, 'hex')
                                    )) = lower(COALESCE(
                                      encode(wrapper_action.canonical_token_id, 'hex'),
                                      NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                    ))
                                AND a.outputs->>'vout' IN (
                                  token_spend.decoded_args->>'tokenOutputIndex',
                                  token_spend.decoded_args->>'changeOutputIndex'
                                )
                                AND (
                                  (
                                    token_spend.decoded_args->>'inputIndex' IS NOT NULL
                                    AND CASE
                                      WHEN wrapper_action.entrypoint = 'wrap'
                                        THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                      WHEN wrapper_action.entrypoint = 'unwrap'
                                        THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                      ELSE NULL
                                    END IS NOT NULL
                                    AND token_spend.decoded_args->>'inputIndex' = CASE
                                      WHEN wrapper_action.entrypoint = 'wrap'
                                        THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                      WHEN wrapper_action.entrypoint = 'unwrap'
                                        THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                      ELSE NULL
                                    END
                                  )
                                  OR (
                                    (
                                      token_spend.decoded_args->>'inputIndex' IS NULL
                                      OR CASE
                                        WHEN wrapper_action.entrypoint = 'wrap'
                                          THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                        WHEN wrapper_action.entrypoint = 'unwrap'
                                          THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                        ELSE NULL
                                      END IS NULL
                                    )
                                    AND 1 = (
                                      SELECT COUNT(*)
                                      FROM covenant_actions legacy_token_spend
                                      JOIN covenants legacy_token_c
                                        ON legacy_token_c.covenant_id = legacy_token_spend.covenant_id
                                      WHERE legacy_token_spend.txid = a.txid
                                        AND legacy_token_spend.action = 'spend'
                                        AND COALESCE(
                                          legacy_token_c.template_name,
                                          legacy_token_c.claimed_template
                                        ) = 'KCC20'
                                        AND lower(COALESCE(
                                              encode(legacy_token_spend.canonical_token_id, 'hex'),
                                              encode(legacy_token_spend.covenant_id, 'hex')
                                            )) = lower(COALESCE(
                                              encode(wrapper_action.canonical_token_id, 'hex'),
                                              NULLIF(
                                                wrapper_action.decoded_args->>'canonicalTokenId',
                                                ''
                                              )
                                            ))
                                    )
                                  )
                                )
                            )
                            OR
                            (
                              wrapper_action.entrypoint = 'wrap'
                              AND a.outputs->>'vout' IN (
                                wrapper_action.decoded_args->>'tokenLockedOutputIndex',
                                wrapper_action.decoded_args->>'orderbookHolderOutputIndex',
                                wrapper_action.decoded_args->>'wrapperOutputIndex'
                              )
                            )
                            OR (
                              wrapper_action.entrypoint = 'unwrap'
                              AND wrapper_action.decoded_args ? 'tokenRecipientOutputIndex'
                              AND a.outputs->>'vout' IN (
                                wrapper_action.decoded_args->>'tokenRecipientOutputIndex',
                                wrapper_action.decoded_args->>'tokenReserveChangeOutputIndex',
                                wrapper_action.decoded_args->>'wrappedChangeOutputIndex',
                                wrapper_action.decoded_args->>'wrapperOutputIndex'
                              )
                            )
                            OR (
                              NOT (
                                wrapper_action.decoded_args ? 'tokenLockedOutputIndex'
                                OR wrapper_action.decoded_args ? 'tokenRecipientOutputIndex'
                                OR wrapper_action.decoded_args ? 'orderbookHolderOutputIndex'
                                OR wrapper_action.decoded_args ? 'wrappedChangeOutputIndex'
                              )
                              AND 1 = (
                                SELECT COUNT(*)
                                FROM covenant_actions token_spend
                                JOIN covenants token_c
                                  ON token_c.covenant_id = token_spend.covenant_id
                                WHERE token_spend.txid = a.txid
                                  AND token_spend.action = 'spend'
                                  AND COALESCE(token_c.template_name, token_c.claimed_template) = 'KCC20'
                                  AND lower(COALESCE(
                                        encode(token_spend.canonical_token_id, 'hex'),
                                        encode(token_spend.covenant_id, 'hex')
                                      )) = lower(COALESCE(
                                        encode(wrapper_action.canonical_token_id, 'hex'),
                                        NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                      ))
                              )
                            )
                          )
                        )
                      )
              )
        )
        UNION ALL
        SELECT
            kcc20_activity_event_id(a.txid, a.action, a.inputs, a.outputs) AS event_id,
            COALESCE(
                a.decoded_args->>'tokenId',
                a.decoded_args->>'listingTokenId',
                a.decoded_args->>'orderedTokenId'
            ) AS token_id_hex,
            a.txid,
            a.block_time_ms,
            a.entrypoint,
            'trade' AS kind,
            CASE
                WHEN a.entrypoint IN ('buy', 'buyListing') THEN 'ask'
                WHEN a.entrypoint = 'fillBuyOrder' THEN 'bid'
                ELSE NULL
            END AS side,
            CASE
                WHEN a.inputs->'previousOutpoint'->>'hash' IS NOT NULL
                    THEN (a.inputs->'previousOutpoint'->>'hash') || ':' || (a.inputs->'previousOutpoint'->>'index')
                ELSE NULL
            END AS order_id,
            COALESCE(
                a.decoded_args->>'seller',
                a.decoded_args->>'listingSeller',
                a.decoded_args->>'buyer',
                a.decoded_args->>'orderBuyer'
            ) AS owner_identifier,
            CASE
                WHEN COALESCE(
                    a.decoded_args->>'seller',
                    a.decoded_args->>'listingSeller',
                    a.decoded_args->>'buyer',
                    a.decoded_args->>'orderBuyer'
                ) IS NOT NULL THEN 0::SMALLINT
                ELSE NULL
            END AS owner_identifier_type,
            COALESCE(
                a.decoded_args->>'tokenAmount',
                a.decoded_args->>'listingTokenAmount',
                a.decoded_args->>'orderedTokenAmount'
            ) AS token_amount,
            CASE
                WHEN COALESCE(
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount'
                ) ~ '^[0-9]+$'
                 AND COALESCE(
                    a.decoded_args->>'priceSompi',
                    a.decoded_args->>'listingPriceSompi',
                    a.decoded_args->>'offerPriceSompi'
                ) ~ '^[0-9]+$'
                 AND COALESCE(
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount'
                )::NUMERIC > 0
                THEN (
                    COALESCE(
                        a.decoded_args->>'priceSompi',
                        a.decoded_args->>'listingPriceSompi',
                        a.decoded_args->>'offerPriceSompi'
                    )::NUMERIC
                    / COALESCE(
                        a.decoded_args->>'tokenAmount',
                        a.decoded_args->>'listingTokenAmount',
                        a.decoded_args->>'orderedTokenAmount'
                    )::NUMERIC
                )::TEXT
                ELSE NULL
            END AS unit_price_sompi,
            COALESCE(
                a.decoded_args->>'priceSompi',
                a.decoded_args->>'listingPriceSompi',
                a.decoded_args->>'offerPriceSompi'
            ) AS price_sompi
        FROM covenant_actions a
        __KCC20_ACTIVITY_REFRESH_SCOPE_JOIN__
        JOIN covenants c ON c.covenant_id = a.covenant_id
        WHERE __KCC20_ACTIVITY_REFRESH_SCOPE_FILTER__
          AND COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
          AND c.claim_verified = TRUE
          AND a.action = 'spend'
          AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        UNION ALL
        SELECT kcc20_activity_fill_event_id(a.txid, a.input_index),a.token_id_hex,a.txid,a.block_time_ms,a.entrypoint,'trade',
               CASE WHEN a.side='sell' THEN 'bid' ELSE 'ask' END,
               a.order_id,a.taker,a.taker_scheme,a.token_amount,a.unit_price_sompi,a.price_sompi
        FROM kcc20_fee_trade_executions a
        __KCC20_ACTIVITY_REFRESH_SCOPE_JOIN__
        WHERE __KCC20_ACTIVITY_REFRESH_SCOPE_FILTER__
        )
        SELECT
            event_id,
            decode(token_id_hex, 'hex'),
            txid,
            block_time_ms,
            entrypoint,
            kind,
            side,
            order_id,
            owner_identifier,
            owner_identifier_type,
            1::SMALLINT,
            token_amount,
            unit_price_sompi,
            price_sompi
        FROM activity
        WHERE token_id_hex ~ '^[0-9a-fA-F]{64}$'
        "#,
        scoped_only,
    );
    let inserted = sqlx::query(AssertSqlSafe(inserted_sql))
        .bind(refresh_from_ms)
        .bind(target_dirty_id)
        .execute(&mut *tx)
        .await?;
    let rows_deleted = deleted.rows_affected();
    let rows_inserted = inserted.rows_affected();
    sqlx::query(
        r#"
        INSERT INTO kcc20_projection_state (name, last_dirty_id, refreshed_at_ms)
        VALUES ($1, $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
        ON CONFLICT (name) DO UPDATE SET
            last_dirty_id = GREATEST(kcc20_projection_state.last_dirty_id, EXCLUDED.last_dirty_id),
            refreshed_at_ms = EXCLUDED.refreshed_at_ms
        "#,
    )
    .bind(KCC20_ACTIVITY_FEED_PROJECTION)
    .bind(target_dirty_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let stats = Kcc20ActivityFeedRefreshStats {
        target_dirty_id,
        last_dirty_id,
        dirty_rows,
        activity_dirty_rows,
        scoped_dirty_txids,
        mode,
        refresh_from_ms,
        rows_deleted,
        rows_inserted,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    tracing::info!(
        target: "kcc20_projector",
        projection = KCC20_ACTIVITY_FEED_PROJECTION,
        target_dirty_id,
        last_dirty_id,
        dirty_rows,
        activity_dirty_rows,
        scoped_dirty_txids,
        mode = ?mode,
        refresh_from_ms,
        rows_deleted,
        rows_inserted,
        elapsed_ms = stats.elapsed_ms,
        "refreshed KCC20 activity feed"
    );

    // Resolve legacy projection rows incrementally instead of deleting or
    // rebuilding the feed during a migration. This is deliberately a separate
    // best-effort transaction so backfill pressure cannot roll back or fail the
    // live incremental refresh.
    let backfill_result: Result<()> = async {
        let mut backfill_tx = pool.begin().await?;
        set_local_query_limits(&mut backfill_tx, "2s", "30s").await?;
        sqlx::query(
            r#"
        WITH batch AS (
            SELECT id, txid, owner_identifier
            FROM kcc20_activity_feed
            WHERE owner_identifier_type_version = 0
            ORDER BY block_time_ms ASC, txid ASC, id ASC
            LIMIT 500
            FOR UPDATE SKIP LOCKED
        ),
        resolved AS (
            SELECT
                batch.id,
                CASE
                    WHEN batch.owner_identifier IS NULL THEN NULL::SMALLINT
                    WHEN COUNT(candidate.owner_identifier) > 0
                     AND COUNT(candidate.identifier_type) =
                         COUNT(candidate.owner_identifier)
                     AND COUNT(DISTINCT candidate.identifier_type) = 1
                        THEN MIN(candidate.identifier_type)
                    ELSE NULL::SMALLINT
                END AS identifier_type
            FROM batch
            LEFT JOIN covenant_actions action ON action.txid = batch.txid
            LEFT JOIN LATERAL (
                SELECT source.owner_identifier, value.identifier_type
                FROM (
                    VALUES
                        (
                            action.outputs->'state'->>'ownerIdentifier',
                            action.outputs->'state'->>'identifierType'
                        ),
                        (
                            action.decoded_args->>'ownerIdentifier',
                            action.decoded_args->>'identifierType'
                        ),
                        (
                            action.decoded_args->>'stateOwner',
                            action.decoded_args->>'stateOwnerType'
                        ),
                        (action.decoded_args->>'owner', '0'),
                        (action.decoded_args->>'wrappedRecipient', '0'),
                        (action.decoded_args->>'seller', '0'),
                        (action.decoded_args->>'buyer', '0'),
                        (action.decoded_args->>'ticketOwner', '0'),
                        (
                            action.decoded_args->>'toOwner',
                            action.decoded_args->>'toOwnerType'
                        ),
                        (
                            action.decoded_args->>'tokenRecipient',
                            action.decoded_args->>'tokenRecipientScheme'
                        )
                ) AS source(owner_identifier, raw_identifier_type)
                CROSS JOIN LATERAL (
                    SELECT CASE
                        WHEN source.raw_identifier_type ~ '^[012]$'
                            THEN source.raw_identifier_type::SMALLINT
                        ELSE NULL::SMALLINT
                    END AS identifier_type
                ) value
                WHERE lower(source.owner_identifier) = lower(batch.owner_identifier)
            ) candidate ON TRUE
            GROUP BY batch.id, batch.owner_identifier
        )
        UPDATE kcc20_activity_feed feed
        SET
            owner_identifier_type = resolved.identifier_type,
            owner_identifier_type_version = CASE
                WHEN feed.owner_identifier IS NULL
                  OR resolved.identifier_type IS NOT NULL
                THEN 1
                ELSE 2
            END
        FROM resolved
        WHERE feed.id = resolved.id
        "#,
        )
        .execute(&mut *backfill_tx)
        .await?;
        backfill_tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(error) = backfill_result {
        tracing::warn!(%error, "KCC20 activity owner-type backfill batch failed");
    }
    Ok(stats)
}

pub async fn kcc20_market_discovery(
    pool: &PgPool,
    token_id_hex: Option<&str>,
    sort_by: &str,
    sort_direction: &str,
    limit: i64,
    offset: i64,
    include_total: bool,
) -> Result<Kcc20MarketDiscoveryPage> {
    let token_id = token_id_hex.map(hex::decode).transpose()?;
    let sort_column = match sort_by {
        "tokenId" | "tokenIdHex" => "m.token_id",
        "bestAskUnitPriceSompi" => "m.best_ask_unit_price_sompi",
        "bestBidUnitPriceSompi" => "m.best_bid_unit_price_sompi",
        "spreadSompi" => "m.spread_sompi",
        "openAskCount" => "m.open_ask_count",
        "openBidCount" => "m.open_bid_count",
        "totalVolumeSompi" => "m.total_volume_sompi",
        "totalTrades" => "m.total_trades",
        "volume24hSompi" => "m.volume_24h_sompi",
        "volume7dSompi" => "m.volume_7d_sompi",
        "tradeCount24h" => "m.trade_count_24h",
        "tradeCount7d" => "m.trade_count_7d",
        "lastTradeTimeMs" => "m.last_trade_time_ms",
        _ => "m.last_trade_time_ms",
    };
    let sort_dir = if sort_direction.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    };
    let order_by = if sort_column == "m.token_id" {
        format!("{sort_column} {sort_dir}")
    } else {
        format!("{sort_column} {sort_dir} NULLS LAST, m.token_id ASC")
    };
    let sql = format!(
        r#"
        SELECT
            encode(m.token_id, 'hex') AS token_id_hex,
            m.best_ask_unit_price_sompi::TEXT AS best_ask_unit_price_sompi,
            m.best_bid_unit_price_sompi::TEXT AS best_bid_unit_price_sompi,
            m.spread_sompi::TEXT AS spread_sompi,
            m.open_ask_count,
            m.open_bid_count,
            m.total_volume_sompi::TEXT AS total_volume_sompi,
            m.total_trades,
            COALESCE(m.volume_24h_sompi, 0)::TEXT AS volume_24h_sompi,
            COALESCE(m.volume_7d_sompi, 0)::TEXT AS volume_7d_sompi,
            COALESCE(m.trade_count_24h, 0)::BIGINT AS trade_count_24h,
            COALESCE(m.trade_count_7d, 0)::BIGINT AS trade_count_7d,
            encode(m.last_trade_txid, 'hex') AS last_trade_txid_hex,
            m.last_trade_time_ms,
            m.refreshed_at_ms,
            m.source_blue_score
        FROM kcc20_market_summaries m
        WHERE ($1::BYTEA IS NULL OR m.token_id = $1)
        ORDER BY {order_by}
        LIMIT $2 OFFSET $3
        "#,
    );
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(&token_id)
        .bind(limit.max(0))
        .bind(offset.max(0))
        .fetch_all(pool)
        .await?;

    let items = rows
        .into_iter()
        .map(|r| Kcc20MarketDiscoveryRow {
            token_id_hex: r.get("token_id_hex"),
            best_ask_unit_price_sompi: r.get("best_ask_unit_price_sompi"),
            best_bid_unit_price_sompi: r.get("best_bid_unit_price_sompi"),
            spread_sompi: r.get("spread_sompi"),
            open_ask_count: r.get("open_ask_count"),
            open_bid_count: r.get("open_bid_count"),
            total_volume_sompi: r.get("total_volume_sompi"),
            total_trades: r.get("total_trades"),
            volume_24h_sompi: r.get("volume_24h_sompi"),
            volume_7d_sompi: r.get("volume_7d_sompi"),
            trade_count_24h: r.get("trade_count_24h"),
            trade_count_7d: r.get("trade_count_7d"),
            last_trade_txid_hex: r.get("last_trade_txid_hex"),
            last_trade_time_ms: r.get("last_trade_time_ms"),
            refreshed_at_ms: r.get("refreshed_at_ms"),
            source_blue_score: r.get("source_blue_score"),
        })
        .collect();

    let total = if include_total {
        Some(
            sqlx::query_scalar(
                r#"
                SELECT COUNT(*)::BIGINT
                FROM kcc20_market_summaries
                WHERE ($1::BYTEA IS NULL OR token_id = $1)
                "#,
            )
            .bind(&token_id)
            .fetch_one(pool)
            .await?,
        )
    } else {
        None
    };

    let freshness_row = sqlx::query(
        r#"
        SELECT
            MAX(refreshed_at_ms) AS refreshed_at_ms,
            MAX(source_blue_score) AS source_blue_score,
            COUNT(*)::BIGINT AS row_count
        FROM kcc20_market_summaries
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(Kcc20MarketDiscoveryPage {
        items,
        total,
        freshness: Kcc20MarketDiscoveryFreshness {
            refreshed_at_ms: freshness_row.get("refreshed_at_ms"),
            source_blue_score: freshness_row.get("source_blue_score"),
            row_count: freshness_row.get("row_count"),
        },
    })
}

/// Discover versioned fee markets without classifying them as legacy wrappers.
/// Only an active, authenticated wrapper role can make a market discoverable.
// Shared by discovery and supply projection: labels and payload claims alone
// must never turn a P2SH balance into an authenticated wrapper reserve.
async fn authenticated_fee_wrapper_rows(
    connection: &mut PgConnection,
    canonical_token_id: Option<&str>,
) -> Result<Vec<PgRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            encode(c.covenant_id, 'hex') AS market_id_hex,
            lower(wrapper.state->>'canonicalTokenId') AS canonical_token_id,
            wrapper.address,
            wrapper.state AS wrapper_state,
            wrapper.script_pubkey AS wrapper_script_pubkey,
            encode(c.genesis_txid, 'hex') AS genesis_txid_hex,
            (
                SELECT COUNT(*)::BIGINT FROM covenant_utxos active
                WHERE active.covenant_id = c.covenant_id
                  AND active.status = 'active'
            ) AS active_utxos,
            wrapper.state->>'enabled' = 'true' AS enabled,
            lower(wrapper.state->>'feeTicketId') AS fee_ticket_id,
            wrapper.blue_score AS source_blue_score
        FROM (
            SELECT DISTINCT ON (u.covenant_id)
                u.covenant_id, u.address, u.state, u.script_pubkey, b.blue_score
            FROM covenant_utxos u
            LEFT JOIN blocks b ON b.hash = u.created_block
            WHERE u.status = 'active'
              AND ($1::TEXT IS NULL OR lower(u.state->>'canonicalTokenId') = $1)
              AND u.state->>'authenticatedMarketId' = encode(u.covenant_id, 'hex')
              AND u.state->>'feePolicyVersion' = '1'
              AND u.state ? 'feePolicy'
              AND u.state ? 'enabled'
              AND u.state->>'canonicalTokenId' ~ '^[0-9a-fA-F]{64}$'
              AND u.state->>'feeTicketId' ~ '^[0-9a-fA-F]{64}$'
            ORDER BY u.covenant_id, b.blue_score DESC NULLS LAST, u.txid DESC, u.vout DESC
        ) wrapper
        JOIN covenants c ON c.covenant_id = wrapper.covenant_id
        WHERE ($1::TEXT IS NULL OR lower(wrapper.state->>'canonicalTokenId') = $1)
        ORDER BY c.covenant_id ASC
        "#,
    )
    .bind(canonical_token_id)
    .fetch_all(connection)
    .await?;

    Ok(rows
        .into_iter()
        .filter(|row| {
            tn12_indexer_decoder::kcc20_fee_v1::fee_market_wrapper_matches_script_pubkey(
                &row.get::<Value, _>("wrapper_state"),
                &row.get::<Vec<u8>, _>("wrapper_script_pubkey"),
            )
        })
        .collect())
}

pub async fn kcc20_fee_markets_by_canonical(
    pool: &PgPool,
    canonical_token_id_hex: &str,
) -> Result<Vec<Kcc20FeeMarketDiscoveryRow>> {
    let canonical_token_id = canonical_token_id_hex.to_ascii_lowercase();
    let rows = authenticated_fee_wrapper_rows(
        &mut *pool.acquire().await?,
        Some(&canonical_token_id),
    )
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            tn12_indexer_decoder::kcc20_fee_v1::fee_market_wrapper_template(
                &r.get::<Value, _>("wrapper_state"),
                &r.get::<Vec<u8>, _>("wrapper_script_pubkey"),
            )
            .map(|template| (r, template.to_owned()))
        })
        .map(|(r, wrapper_template)| Kcc20FeeMarketDiscoveryRow {
            wrapper_template,
            market_id_hex: r.get("market_id_hex"),
            canonical_token_id: r.get("canonical_token_id"),
            address: r.get("address"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            active_utxos: r.get("active_utxos"),
            enabled: r.get("enabled"),
            fee_ticket_id: r.get("fee_ticket_id"),
            source_blue_score: r.get("source_blue_score"),
        })
        .collect())
}

pub async fn kcc20_wrapper_summaries_by_canonical(
    pool: &PgPool,
    canonical_token_id_hex: &str,
    include_pending: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20WrapperSummaryRow>> {
    let canonical_token_id = hex::decode(canonical_token_id_hex)?;
    let rows = sqlx::query(
        r#"
        SELECT
            encode(wrapper_id, 'hex') AS wrapper_id_hex,
            encode(wrapper_id, 'hex') AS market_id_hex,
            encode(canonical_token_id, 'hex') AS canonical_token_id,
            encode(canonical_token_id, 'hex') AS claimed_canonical_token_id,
            encode(canonical_token_id, 'hex') AS contract_canonical_token_id,
            address,
            encode(genesis_txid, 'hex') AS genesis_txid_hex,
            active_utxos,
            pending_reveal,
            enabled,
            encode(fee_ticket_id, 'hex') AS fee_ticket_id,
            wrapped_root_amount::TEXT AS wrapped_root_amount,
            classification_kind,
            classification_status,
            claim_source,
            refreshed_at_ms,
            source_blue_score
        FROM kcc20_wrapper_summaries
        WHERE canonical_token_id = $1
          AND ($2::BOOLEAN OR NOT pending_reveal)
        ORDER BY active_utxos DESC, pending_reveal ASC, wrapper_id ASC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(canonical_token_id)
    .bind(include_pending)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Kcc20WrapperSummaryRow {
            wrapper_id_hex: r.get("wrapper_id_hex"),
            market_id_hex: r.get("market_id_hex"),
            canonical_token_id: r.get("canonical_token_id"),
            claimed_canonical_token_id: r.get("claimed_canonical_token_id"),
            contract_canonical_token_id: r.get("contract_canonical_token_id"),
            address: r.get("address"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            active_utxos: r.get("active_utxos"),
            pending_reveal: r.get("pending_reveal"),
            enabled: r.get("enabled"),
            fee_ticket_id: r.get("fee_ticket_id"),
            wrapped_root_amount: r.get("wrapped_root_amount"),
            classification_kind: r.get("classification_kind"),
            classification_status: r.get("classification_status"),
            claim_source: r.get("claim_source"),
            refreshed_at_ms: r.get("refreshed_at_ms"),
            source_blue_score: r.get("source_blue_score"),
        })
        .collect())
}

pub async fn kcc20_wrapper_summaries_by_canonical_count(
    pool: &PgPool,
    canonical_token_id_hex: &str,
    include_pending: bool,
) -> Result<i64> {
    let canonical_token_id = hex::decode(canonical_token_id_hex)?;
    let count = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM kcc20_wrapper_summaries
        WHERE canonical_token_id = $1
          AND ($2::BOOLEAN OR NOT pending_reveal)
        "#,
    )
    .bind(canonical_token_id)
    .bind(include_pending)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn kcc20_wrapper_summaries(
    pool: &PgPool,
    include_pending: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20WrapperSummaryRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            encode(wrapper_id, 'hex') AS wrapper_id_hex,
            encode(wrapper_id, 'hex') AS market_id_hex,
            encode(canonical_token_id, 'hex') AS canonical_token_id,
            encode(canonical_token_id, 'hex') AS claimed_canonical_token_id,
            encode(canonical_token_id, 'hex') AS contract_canonical_token_id,
            address,
            encode(genesis_txid, 'hex') AS genesis_txid_hex,
            active_utxos,
            pending_reveal,
            enabled,
            encode(fee_ticket_id, 'hex') AS fee_ticket_id,
            wrapped_root_amount::TEXT AS wrapped_root_amount,
            classification_kind,
            classification_status,
            claim_source,
            refreshed_at_ms,
            source_blue_score
        FROM kcc20_wrapper_summaries
        WHERE ($1::BOOLEAN OR NOT pending_reveal)
        ORDER BY active_utxos DESC, pending_reveal ASC, wrapper_id ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(include_pending)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Kcc20WrapperSummaryRow {
            wrapper_id_hex: r.get("wrapper_id_hex"),
            market_id_hex: r.get("market_id_hex"),
            canonical_token_id: r.get("canonical_token_id"),
            claimed_canonical_token_id: r.get("claimed_canonical_token_id"),
            contract_canonical_token_id: r.get("contract_canonical_token_id"),
            address: r.get("address"),
            genesis_txid_hex: r.get("genesis_txid_hex"),
            active_utxos: r.get("active_utxos"),
            pending_reveal: r.get("pending_reveal"),
            enabled: r.get("enabled"),
            fee_ticket_id: r.get("fee_ticket_id"),
            wrapped_root_amount: r.get("wrapped_root_amount"),
            classification_kind: r.get("classification_kind"),
            classification_status: r.get("classification_status"),
            claim_source: r.get("claim_source"),
            refreshed_at_ms: r.get("refreshed_at_ms"),
            source_blue_score: r.get("source_blue_score"),
        })
        .collect())
}

pub async fn kcc20_wrapper_summaries_count(pool: &PgPool, include_pending: bool) -> Result<i64> {
    let count = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM kcc20_wrapper_summaries
        WHERE ($1::BOOLEAN OR NOT pending_reveal)
        "#,
    )
    .bind(include_pending)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn kcc20_token_summary(
    pool: &PgPool,
    token_id_hex: &str,
) -> Result<Option<Kcc20TokenSummaryRow>> {
    let token_id = hex::decode(token_id_hex)?;
    let row = sqlx::query(
        r#"
        SELECT
            encode(token_id, 'hex') AS token_id_hex,
            holder_count,
            holder_supply::TEXT AS holder_supply,
            remaining_supply::TEXT,
            active_mint_policy_value,
            public_mint_active,
            wrapper_reserve_supply::TEXT AS wrapper_reserve_supply,
            orderbook_tradeable_supply::TEXT AS orderbook_tradeable_supply,
            top_holders,
            encode(wrapper_id, 'hex') AS wrapper_id_hex,
            refreshed_at_ms,
            source_blue_score
        FROM kcc20_token_summaries
        WHERE token_id = $1
        "#,
    )
    .bind(token_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Kcc20TokenSummaryRow {
        token_id_hex: r.get("token_id_hex"),
        holder_count: r.get("holder_count"),
        holder_supply: r.get("holder_supply"),
        remaining_supply: r.get("remaining_supply"),
        active_mint_policy_value: r.get("active_mint_policy_value"),
        public_mint_active: r.get("public_mint_active"),
        wrapper_reserve_supply: r.get("wrapper_reserve_supply"),
        orderbook_tradeable_supply: r.get("orderbook_tradeable_supply"),
        top_holders: r.get("top_holders"),
        wrapper_id_hex: r.get("wrapper_id_hex"),
        refreshed_at_ms: r.get("refreshed_at_ms"),
        source_blue_score: r.get("source_blue_score"),
    }))
}

pub async fn kcc20_fast_freshness(pool: &PgPool) -> Result<Kcc20FastFreshness> {
    let cursor_row = sqlx::query(
        r#"SELECT key, value, updated_at_ms,
                  GREATEST(
                      EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - updated_at_ms,
                      0
                  ) AS cursor_age_ms
           FROM indexer_state
           WHERE key IN (
               'chain_live_near_tip_repair_cursor',
               'chain_live_repair_cursor',
               'chain_realtime_tip_cursor',
               'chain_live_scan_cursor',
               'chain_scan_cursor'
           )
           ORDER BY CASE key
               WHEN 'chain_live_near_tip_repair_cursor' THEN 0
               WHEN 'chain_live_repair_cursor' THEN 1
               WHEN 'chain_realtime_tip_cursor' THEN 2
               WHEN 'chain_live_scan_cursor' THEN 3
               ELSE 4
           END
           LIMIT 1"#,
    )
    .fetch_optional(pool)
    .await?;
    let (
        cursor_key,
        cursor_blue_score,
        rest_database_blue_score,
        rest_database_observed_at_ms,
        cursor_updated_at_ms,
        cursor_age_ms,
    ) = cursor_row
        .map(|r| {
            let value: Value = r.get("value");
            (
                Some(r.get::<String, _>("key")),
                value.get("blue_score").and_then(Value::as_i64),
                value
                    .get("rest_database_blue_score")
                    .and_then(Value::as_i64),
                value
                    .get("rest_database_observed_at_ms")
                    .and_then(Value::as_i64)
                    .or_else(|| Some(r.get::<i64, _>("updated_at_ms"))),
                Some(r.get::<i64, _>("updated_at_ms")),
                Some(r.get::<i64, _>("cursor_age_ms")),
            )
        })
        .unwrap_or((None, None, None, None, None, None));

    let latest_block_row = sqlx::query(
        r#"SELECT blue_score, timestamp_ms, indexed_at_ms
           FROM blocks
           WHERE is_chain_block
           ORDER BY blue_score DESC
           LIMIT 1"#,
    )
    .fetch_optional(pool)
    .await?;
    let (latest_block_blue_score, latest_block_time_ms, latest_block_indexed_at_ms) =
        latest_block_row
            .map(|r| {
                (
                    Some(r.get::<i64, _>("blue_score")),
                    Some(r.get::<i64, _>("timestamp_ms")),
                    Some(r.get::<i64, _>("indexed_at_ms")),
                )
            })
            .unwrap_or((None, None, None));

    let latest_action_time_ms: Option<i64> = sqlx::query_scalar(
        r#"SELECT block_time_ms
           FROM covenant_actions
           ORDER BY block_time_ms DESC
           LIMIT 1"#,
    )
    .fetch_optional(pool)
    .await?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let heartbeat_row = sqlx::query(
        "SELECT value, updated_at_ms FROM indexer_state WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .fetch_optional(pool)
    .await?;
    let (live_acceptance_blue_score, live_acceptance_observed_at_ms) = heartbeat_row
        .map(|row| {
            let value: Value = row.get("value");
            (
                value.get("blue_score").and_then(Value::as_i64),
                Some(row.get::<i64, _>("updated_at_ms")),
            )
        })
        .unwrap_or((None, None));
    let live_acceptance_age_ms = live_acceptance_observed_at_ms
        .map(|observed_at_ms| now_ms.saturating_sub(observed_at_ms).max(0));
    let live_acceptance_fresh =
        live_acceptance_age_ms.is_some_and(|age_ms| age_ms <= LIVE_ACCEPTANCE_FRESH_MS);
    let rest_observation_age_ms = rest_database_blue_score
        .and(rest_database_observed_at_ms)
        .map(|observed_at_ms| now_ms.saturating_sub(observed_at_ms).max(0));
    let rest_observation_fresh =
        rest_observation_age_ms.is_some_and(|age_ms| age_ms <= REST_OBSERVATION_FRESH_MS);
    let db_cursor_lag_blocks = match (rest_database_blue_score, cursor_blue_score) {
        _ if !rest_observation_fresh => None,
        (Some(latest), Some(cursor)) => Some((latest - cursor).max(0)),
        _ => None,
    };
    let rest_db_lag_blocks = rest_db_lag_blocks(
        latest_block_blue_score.max(live_acceptance_blue_score),
        rest_database_blue_score,
    );
    let lag = db_cursor_lag_blocks.unwrap_or(i64::MAX);
    let cursor_age = cursor_age_ms.unwrap_or(i64::MAX);
    let projections = kcc20_projection_freshness(pool).await?;
    let projections_ok = !projections.market.pending
        && !projections.token_page.pending
        && !projections.activity_feed.pending
        && !projections.owner_orders.pending
        && !projections.owner_portfolio_assets.pending;
    let projections_stale = projection_is_stale(&projections.market)
        || projection_is_stale(&projections.token_page)
        || projection_is_stale(&projections.activity_feed)
        || projection_is_stale(&projections.owner_orders)
        || projection_is_stale(&projections.owner_portfolio_assets);
    Ok(Kcc20FastFreshness {
        ok: lag <= 10
            && cursor_age <= 30_000
            && rest_db_lag_blocks.is_none_or(|lag| lag <= REST_DB_MAX_LAG_BLOCKS)
            && projections_ok
            && (live_acceptance_age_ms.is_none() || live_acceptance_fresh),
        suggested_poll_ms: if lag <= 10
            && cursor_age <= 30_000
            && rest_db_lag_blocks.is_none_or(|lag| lag <= REST_DB_MAX_LAG_BLOCKS)
            && projections_ok
            && (live_acceptance_age_ms.is_none() || live_acceptance_fresh)
        {
            5000
        } else {
            15000
        },
        stale: lag > 100
            || cursor_age > 60_000
            || rest_db_lag_blocks.is_some_and(|lag| lag > REST_DB_MAX_LAG_BLOCKS)
            || projections_stale
            || live_acceptance_age_ms.is_some_and(|_| !live_acceptance_fresh),
        scanner: ScannerHealth {
            cursor_key,
            cursor_blue_score,
            rest_database_blue_score,
            cursor_updated_at_ms,
            cursor_age_ms,
            rest_observation_age_ms,
            rest_observation_fresh,
            live_acceptance_observed_at_ms,
            live_acceptance_blue_score,
            live_acceptance_age_ms,
            live_acceptance_fresh,
            latest_block_blue_score,
            latest_block_time_ms,
            latest_block_indexed_at_ms,
            latest_action_time_ms,
            db_cursor_lag_blocks,
            rest_db_lag_blocks,
        },
        projections,
    })
}

fn projection_is_stale(projection: &Kcc20ProjectionStateFreshness) -> bool {
    projection.pending && projection.pending_age_ms.is_some_and(|age| age > 60_000)
}

pub async fn kcc20_projection_freshness(pool: &PgPool) -> Result<Kcc20ProjectionFreshness> {
    let row = sqlx::query(
        r#"
        WITH dirty AS (
            SELECT
                COALESCE(MAX(id), 0)::BIGINT AS latest_dirty_id,
                MAX(created_at_ms) AS latest_dirty_at_ms
            FROM kcc20_projection_dirty
        ),
        states AS (
            SELECT name, last_dirty_id, refreshed_at_ms
            FROM kcc20_projection_state
            WHERE name IN ('market', 'token_page', 'activity_feed', 'owner_orders', 'owner_portfolio_assets')
        )
        SELECT
            dirty.latest_dirty_id,
            dirty.latest_dirty_at_ms,
            COALESCE(market.last_dirty_id, 0)::BIGINT AS market_last_dirty_id,
            market.refreshed_at_ms AS market_refreshed_at_ms,
            COALESCE(token_page.last_dirty_id, 0)::BIGINT AS token_page_last_dirty_id,
            token_page.refreshed_at_ms AS token_page_refreshed_at_ms,
            COALESCE(activity_feed.last_dirty_id, 0)::BIGINT AS activity_feed_last_dirty_id,
            activity_feed.refreshed_at_ms AS activity_feed_refreshed_at_ms,
            COALESCE(owner_orders.last_dirty_id, 0)::BIGINT AS owner_orders_last_dirty_id,
            owner_orders.refreshed_at_ms AS owner_orders_refreshed_at_ms,
            COALESCE(owner_portfolio.last_dirty_id, 0)::BIGINT AS owner_portfolio_last_dirty_id,
            owner_portfolio.refreshed_at_ms AS owner_portfolio_refreshed_at_ms,
            CASE
                WHEN dirty.latest_dirty_id > COALESCE(market.last_dirty_id, 0)
                THEN GREATEST(
                    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - (
                        SELECT MIN(created_at_ms)
                        FROM kcc20_projection_dirty
                        WHERE id > COALESCE(market.last_dirty_id, 0)
                    ),
                    0
                )
                ELSE NULL
            END AS market_pending_age_ms,
            CASE
                WHEN dirty.latest_dirty_id > COALESCE(token_page.last_dirty_id, 0)
                THEN GREATEST(
                    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - (
                        SELECT MIN(created_at_ms)
                        FROM kcc20_projection_dirty
                        WHERE id > COALESCE(token_page.last_dirty_id, 0)
                    ),
                    0
                )
                ELSE NULL
            END AS token_page_pending_age_ms,
            CASE
                WHEN dirty.latest_dirty_id > COALESCE(activity_feed.last_dirty_id, 0)
                THEN GREATEST(
                    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - (
                        SELECT MIN(created_at_ms)
                        FROM kcc20_projection_dirty
                        WHERE id > COALESCE(activity_feed.last_dirty_id, 0)
                    ),
                    0
                )
                ELSE NULL
            END AS activity_feed_pending_age_ms,
            CASE
                WHEN dirty.latest_dirty_id > COALESCE(owner_orders.last_dirty_id, 0)
                THEN GREATEST(
                    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - (
                        SELECT MIN(created_at_ms)
                        FROM kcc20_projection_dirty
                        WHERE id > COALESCE(owner_orders.last_dirty_id, 0)
                    ),
                    0
                )
                ELSE NULL
            END AS owner_orders_pending_age_ms,
            CASE
                WHEN dirty.latest_dirty_id > COALESCE(owner_portfolio.last_dirty_id, 0)
                THEN GREATEST(
                    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - (
                        SELECT MIN(created_at_ms)
                        FROM kcc20_projection_dirty
                        WHERE id > COALESCE(owner_portfolio.last_dirty_id, 0)
                    ),
                    0
                )
                ELSE NULL
            END AS owner_portfolio_pending_age_ms
        FROM dirty
        LEFT JOIN states market ON market.name = 'market'
        LEFT JOIN states token_page ON token_page.name = 'token_page'
        LEFT JOIN states activity_feed ON activity_feed.name = 'activity_feed'
        LEFT JOIN states owner_orders ON owner_orders.name = 'owner_orders'
        LEFT JOIN states owner_portfolio ON owner_portfolio.name = 'owner_portfolio_assets'
        "#,
    )
    .fetch_one(pool)
    .await?;

    let latest_dirty_id = row.get::<i64, _>("latest_dirty_id");
    let market_last_dirty_id = row.get::<i64, _>("market_last_dirty_id");
    let token_page_last_dirty_id = row.get::<i64, _>("token_page_last_dirty_id");
    let activity_feed_last_dirty_id = row.get::<i64, _>("activity_feed_last_dirty_id");
    let owner_orders_last_dirty_id = row.get::<i64, _>("owner_orders_last_dirty_id");
    let owner_portfolio_last_dirty_id = row.get::<i64, _>("owner_portfolio_last_dirty_id");
    Ok(Kcc20ProjectionFreshness {
        latest_dirty_id,
        latest_dirty_at_ms: row.get("latest_dirty_at_ms"),
        market: Kcc20ProjectionStateFreshness {
            name: KCC20_MARKET_PROJECTION.to_string(),
            last_dirty_id: market_last_dirty_id,
            refreshed_at_ms: row.get("market_refreshed_at_ms"),
            pending: latest_dirty_id > market_last_dirty_id,
            pending_age_ms: row.get("market_pending_age_ms"),
        },
        token_page: Kcc20ProjectionStateFreshness {
            name: KCC20_TOKEN_PAGE_PROJECTION.to_string(),
            last_dirty_id: token_page_last_dirty_id,
            refreshed_at_ms: row.get("token_page_refreshed_at_ms"),
            pending: latest_dirty_id > token_page_last_dirty_id,
            pending_age_ms: row.get("token_page_pending_age_ms"),
        },
        activity_feed: Kcc20ProjectionStateFreshness {
            name: KCC20_ACTIVITY_FEED_PROJECTION.to_string(),
            last_dirty_id: activity_feed_last_dirty_id,
            refreshed_at_ms: row.get("activity_feed_refreshed_at_ms"),
            pending: latest_dirty_id > activity_feed_last_dirty_id,
            pending_age_ms: row.get("activity_feed_pending_age_ms"),
        },
        owner_orders: Kcc20ProjectionStateFreshness {
            name: KCC20_OWNER_ORDERS_PROJECTION.to_string(),
            last_dirty_id: owner_orders_last_dirty_id,
            refreshed_at_ms: row.get("owner_orders_refreshed_at_ms"),
            pending: latest_dirty_id > owner_orders_last_dirty_id,
            pending_age_ms: row.get("owner_orders_pending_age_ms"),
        },
        owner_portfolio_assets: Kcc20ProjectionStateFreshness {
            name: KCC20_OWNER_PORTFOLIO_ASSETS_PROJECTION.to_string(),
            last_dirty_id: owner_portfolio_last_dirty_id,
            refreshed_at_ms: row.get("owner_portfolio_refreshed_at_ms"),
            pending: latest_dirty_id > owner_portfolio_last_dirty_id,
            pending_age_ms: row.get("owner_portfolio_pending_age_ms"),
        },
    })
}

pub async fn kcc20_token_stats(
    pool: &PgPool,
    token_id_hex: &str,
    window_ms: i64,
) -> Result<Kcc20TokenStatsRow> {
    let window_ms = window_ms.max(1);
    let mut tx = pool.begin().await?;
    set_local_kcc20_orderbook_limits(&mut tx).await?;
    let row = sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH orderbook_trade_actions AS MATERIALIZED (
            SELECT * FROM covenant_actions
            WHERE action = 'spend'
              AND entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
        ), trades AS (
            SELECT
                COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(holder.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                encode(a.txid, 'hex')        AS txid_hex,
                a.block_time_ms              AS block_time_ms,
                COALESCE(
                    NULLIF(a.decoded_args->>'fillAmount', ''),
                    holder.outputs->'state'->>'amount'
                ) AS token_amount,
                a.decoded_args->>'unitPriceSompi' AS unit_price_sompi,
                CASE
                    WHEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount') IS NOT NULL
                     AND a.decoded_args->>'unitPriceSompi' IS NOT NULL
                    THEN FLOOR(
                        COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount')::NUMERIC
                        * (a.decoded_args->>'unitPriceSompi')::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM orderbook_trade_actions a
            -- Keep sparse trade lookups from hashing the entire covenant registry.
            CROSS JOIN LATERAL (
                SELECT * FROM covenants candidate
                WHERE candidate.covenant_id = a.covenant_id
                OFFSET 0
            ) c
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions holder
                WHERE holder.covenant_id = a.covenant_id
                  AND holder.txid = a.txid
                  AND holder.action = 'continuation'
                  AND holder.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (holder.outputs ? 'vout') DESC,
                  holder.id DESC
                LIMIT 1
            ) holder ON TRUE
            WHERE (
                COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                OR a.decoded_args->>'supplyBacking' = 'kcc20WrapperReserve'
                OR a.decoded_args ? 'canonicalTokenId'
              )
              AND a.action = 'spend'
              AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
              AND NOT (
                a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__

            UNION ALL
            SELECT token_id_hex,txid_hex,block_time_ms,token_amount,unit_price_sompi,price_sompi FROM kcc20_fee_trade_executions

            UNION ALL

            SELECT
                COALESCE(
                    a.decoded_args->>'tokenId',
                    a.decoded_args->>'listingTokenId',
                    a.decoded_args->>'orderedTokenId'
                ) AS token_id_hex,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms       AS block_time_ms,
                COALESCE(
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount'
                ) AS token_amount,
                CASE
                    WHEN COALESCE(
                        a.decoded_args->>'tokenAmount',
                        a.decoded_args->>'listingTokenAmount',
                        a.decoded_args->>'orderedTokenAmount'
                    ) ~ '^[0-9]+$'
                     AND COALESCE(
                        a.decoded_args->>'priceSompi',
                        a.decoded_args->>'listingPriceSompi',
                        a.decoded_args->>'offerPriceSompi'
                    ) ~ '^[0-9]+$'
                     AND COALESCE(
                        a.decoded_args->>'tokenAmount',
                        a.decoded_args->>'listingTokenAmount',
                        a.decoded_args->>'orderedTokenAmount'
                    )::NUMERIC > 0
                    THEN (
                        COALESCE(
                            a.decoded_args->>'priceSompi',
                            a.decoded_args->>'listingPriceSompi',
                            a.decoded_args->>'offerPriceSompi'
                        )::NUMERIC
                        / COALESCE(
                            a.decoded_args->>'tokenAmount',
                            a.decoded_args->>'listingTokenAmount',
                            a.decoded_args->>'orderedTokenAmount'
                        )::NUMERIC
                    )::TEXT
                    ELSE NULL
                END AS unit_price_sompi,
                COALESCE(
                    a.decoded_args->>'priceSompi',
                    a.decoded_args->>'listingPriceSompi',
                    a.decoded_args->>'offerPriceSompi'
                ) AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
              AND c.claim_verified = TRUE
              AND a.action = 'spend'
              AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        ),
        anchor AS (
            SELECT COALESCE(
                (SELECT MAX(timestamp_ms) FROM blocks WHERE is_chain_block),
                (SELECT MAX(timestamp_ms) FROM blocks),
                (SELECT MAX(block_time_ms) FROM trades),
                0
            ) AS anchor_ms
        ),
        filtered AS (
            SELECT t.*
            FROM trades t
            CROSS JOIN anchor
            WHERE t.token_id_hex = $1
              AND t.block_time_ms >= anchor.anchor_ms - $2::BIGINT
              AND t.unit_price_sompi ~ '^[0-9]+(\.[0-9]+)?$'
        ),
        ranked AS (
            SELECT
                *,
                ROW_NUMBER() OVER (ORDER BY block_time_ms ASC, txid_hex ASC) AS open_rn,
                ROW_NUMBER() OVER (ORDER BY block_time_ms DESC, txid_hex DESC) AS close_rn
            FROM filtered
        )
        SELECT
            $1::TEXT AS token_id_hex,
            MAX(unit_price_sompi) FILTER (WHERE open_rn = 1) AS open_unit_price_sompi,
            MAX(unit_price_sompi) FILTER (WHERE close_rn = 1) AS close_unit_price_sompi,
            MAX(unit_price_sompi::NUMERIC)::TEXT AS high_unit_price_sompi,
            MIN(unit_price_sompi::NUMERIC)::TEXT AS low_unit_price_sompi,
            COALESCE(SUM(
                CASE WHEN price_sompi ~ '^[0-9]+$' THEN price_sompi::NUMERIC ELSE 0 END
            ), 0)::TEXT AS volume_sompi,
            COALESCE(SUM(
                CASE WHEN token_amount ~ '^[0-9]+$' THEN token_amount::NUMERIC ELSE 0 END
            ), 0)::TEXT AS token_volume,
            COUNT(*)::BIGINT AS trade_count
        FROM ranked
        "#,
        )))
    .bind(token_id_hex)
    .bind(window_ms)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let open_unit_price_sompi: Option<String> = row.get("open_unit_price_sompi");
    let close_unit_price_sompi: Option<String> = row.get("close_unit_price_sompi");
    let price_change_sompi = match (
        open_unit_price_sompi
            .as_deref()
            .and_then(parse_numeric_i128),
        close_unit_price_sompi
            .as_deref()
            .and_then(parse_numeric_i128),
    ) {
        (Some(open), Some(close)) => Some((close - open).to_string()),
        _ => None,
    };
    Ok(Kcc20TokenStatsRow {
        token_id_hex: row.get("token_id_hex"),
        window_ms,
        volume_sompi: row.get("volume_sompi"),
        token_volume: row.get("token_volume"),
        trade_count: row.get("trade_count"),
        open_unit_price_sompi,
        high_unit_price_sompi: row.get("high_unit_price_sompi"),
        low_unit_price_sompi: row.get("low_unit_price_sompi"),
        close_unit_price_sompi,
        price_change_sompi,
    })
}

fn parse_numeric_i128(value: &str) -> Option<i128> {
    value
        .split_once('.')
        .map(|(whole, _)| whole)
        .unwrap_or(value)
        .parse::<i128>()
        .ok()
}

pub async fn kcc20_candles(
    pool: &PgPool,
    token_id_hex: &str,
    interval_ms: i64,
    limit: Option<i64>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<Kcc20CandleRow>> {
    let rows = sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH trades AS (
            SELECT
                COALESCE(
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(holder.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                encode(a.txid, 'hex')        AS txid_hex,
                a.block_time_ms              AS block_time_ms,
                COALESCE(
                    NULLIF(a.decoded_args->>'fillAmount', ''),
                    holder.outputs->'state'->>'amount'
                ) AS token_amount,
                a.decoded_args->>'unitPriceSompi' AS unit_price_sompi,
                CASE
                    WHEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount') IS NOT NULL
                     AND a.decoded_args->>'unitPriceSompi' IS NOT NULL
                    THEN FLOOR(
                        COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder.outputs->'state'->>'amount')::NUMERIC
                        * (a.decoded_args->>'unitPriceSompi')::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions holder
                WHERE holder.covenant_id = a.covenant_id
                  AND holder.txid = a.txid
                  AND holder.action = 'continuation'
                  AND holder.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND holder.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (holder.outputs ? 'vout') DESC,
                  holder.id DESC
                LIMIT 1
            ) holder ON TRUE
            WHERE (
                COALESCE(c.template_name, c.claimed_template) = 'KCC20Orderbook'
                OR a.decoded_args->>'supplyBacking' = 'kcc20WrapperReserve'
                OR a.decoded_args ? 'canonicalTokenId'
              )
              AND a.action = 'spend'
              AND a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
              AND NOT (
                a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__

            UNION ALL
            SELECT token_id_hex,txid_hex,block_time_ms,token_amount,unit_price_sompi,price_sompi FROM kcc20_fee_trade_executions

            UNION ALL

            SELECT
                COALESCE(
                    a.decoded_args->>'tokenId',
                    a.decoded_args->>'listingTokenId',
                    a.decoded_args->>'orderedTokenId'
                ) AS token_id_hex,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms       AS block_time_ms,
                COALESCE(
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount'
                ) AS token_amount,
                CASE
                    WHEN COALESCE(
                        a.decoded_args->>'tokenAmount',
                        a.decoded_args->>'listingTokenAmount',
                        a.decoded_args->>'orderedTokenAmount'
                    ) ~ '^[0-9]+$'
                     AND COALESCE(
                        a.decoded_args->>'priceSompi',
                        a.decoded_args->>'listingPriceSompi',
                        a.decoded_args->>'offerPriceSompi'
                    ) ~ '^[0-9]+$'
                     AND COALESCE(
                        a.decoded_args->>'tokenAmount',
                        a.decoded_args->>'listingTokenAmount',
                        a.decoded_args->>'orderedTokenAmount'
                    )::NUMERIC > 0
                    THEN (
                        COALESCE(
                            a.decoded_args->>'priceSompi',
                            a.decoded_args->>'listingPriceSompi',
                            a.decoded_args->>'offerPriceSompi'
                        )::NUMERIC
                        / COALESCE(
                            a.decoded_args->>'tokenAmount',
                            a.decoded_args->>'listingTokenAmount',
                            a.decoded_args->>'orderedTokenAmount'
                        )::NUMERIC
                    )::TEXT
                    ELSE NULL
                END AS unit_price_sompi,
                COALESCE(
                    a.decoded_args->>'priceSompi',
                    a.decoded_args->>'listingPriceSompi',
                    a.decoded_args->>'offerPriceSompi'
                ) AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            WHERE COALESCE(c.template_name, c.claimed_template) IN ('KCC20Sale', 'KCC20SaleV2', 'KCC20BuyOrder')
              AND c.claim_verified = TRUE
              AND a.action = 'spend'
              AND a.entrypoint IN ('buy', 'buyListing', 'fillBuyOrder')
        ),
        filtered AS (
            SELECT
                *,
                ((block_time_ms / $2::BIGINT) * $2::BIGINT) AS bucket_time_ms
            FROM trades
            WHERE token_id_hex = $1
              AND unit_price_sompi ~ '^[0-9]+(\.[0-9]+)?$'
              -- Bound on the BUCKET boundary, not the raw trade timestamp: a
              -- trade's own block_time_ms can fall inside [from, to) while
              -- sibling trades in the same bucket fall outside it (from/to
              -- need not be interval-aligned), which would otherwise silently
              -- compute an incomplete OHLCV for that boundary bucket instead
              -- of cleanly including or excluding it whole.
              AND ($4::BIGINT IS NULL OR ((block_time_ms / $2::BIGINT) * $2::BIGINT) >= $4)
              AND ($5::BIGINT IS NULL OR ((block_time_ms / $2::BIGINT) * $2::BIGINT) < $5)
        ),
        ranked AS (
            SELECT
                *,
                ROW_NUMBER() OVER (PARTITION BY bucket_time_ms ORDER BY block_time_ms ASC, txid_hex ASC) AS open_rn,
                ROW_NUMBER() OVER (PARTITION BY bucket_time_ms ORDER BY block_time_ms DESC, txid_hex DESC) AS close_rn
            FROM filtered
        )
        SELECT
            token_id_hex,
            bucket_time_ms,
            MAX(unit_price_sompi) FILTER (WHERE open_rn = 1) AS open_unit_price_sompi,
            MAX(unit_price_sompi) FILTER (WHERE close_rn = 1) AS close_unit_price_sompi,
            MAX(unit_price_sompi::NUMERIC)::TEXT AS high_unit_price_sompi,
            MIN(unit_price_sompi::NUMERIC)::TEXT AS low_unit_price_sompi,
            COALESCE(SUM(
                CASE WHEN price_sompi ~ '^[0-9]+$' THEN price_sompi::NUMERIC ELSE 0 END
            ), 0)::TEXT AS volume_sompi,
            COALESCE(SUM(
                CASE WHEN token_amount ~ '^[0-9]+$' THEN token_amount::NUMERIC ELSE 0 END
            ), 0)::TEXT AS token_volume,
            COUNT(*)::BIGINT AS trade_count
        FROM ranked
        GROUP BY token_id_hex, bucket_time_ms
        ORDER BY bucket_time_ms DESC
        LIMIT COALESCE($3::BIGINT, 500)
        "#,
        )))
    .bind(token_id_hex)
    .bind(interval_ms.max(1))
    .bind(limit)
    .bind(from_ms)
    .bind(to_ms)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Kcc20CandleRow {
            token_id_hex: r.get("token_id_hex"),
            bucket_time_ms: r.get("bucket_time_ms"),
            open_unit_price_sompi: r.get("open_unit_price_sompi"),
            high_unit_price_sompi: r.get("high_unit_price_sompi"),
            low_unit_price_sompi: r.get("low_unit_price_sompi"),
            close_unit_price_sompi: r.get("close_unit_price_sompi"),
            volume_sompi: r.get("volume_sompi"),
            token_volume: r.get("token_volume"),
            trade_count: r.get("trade_count"),
        })
        .collect())
}

pub async fn kcc20_activity(
    pool: &PgPool,
    token_id_hex: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20ActivityRow>> {
    kcc20_activity_filtered(
        pool,
        token_id_hex,
        &Kcc20ActivityFilter::default(),
        limit,
        offset,
    )
    .await
}

pub async fn kcc20_activity_filtered(
    pool: &PgPool,
    token_id_hex: &str,
    filters: &Kcc20ActivityFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20ActivityRow>> {
    let token_id_hex = token_id_hex.to_ascii_lowercase();
    let normalized_filters = Kcc20ActivityFilter {
        kind: filters.kind.clone(),
        scope: filters
            .scope
            .as_ref()
            .map(|value| value.to_ascii_lowercase()),
        side: filters.side.clone(),
        entrypoint: filters.entrypoint.clone(),
        owner: filters
            .owner
            .as_ref()
            .map(|value| value.to_ascii_lowercase()),
        txid: filters
            .txid
            .as_ref()
            .map(|value| value.to_ascii_lowercase()),
        order_id: filters
            .order_id
            .as_ref()
            .map(|value| value.to_ascii_lowercase()),
        from_ms: filters.from_ms,
        to_ms: filters.to_ms,
    };

    let requested_token_id = hex::decode(&token_id_hex)?;
    let activity_token_id = if table_exists(pool, "kcc20_wrapper_summaries").await? {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT canonical_token_id FROM kcc20_wrapper_summaries WHERE wrapper_id = $1",
        )
        .bind(&requested_token_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| requested_token_id.clone())
    } else {
        requested_token_id.clone()
    };
    let activity_token_id_hex = hex::encode(&activity_token_id);

    if table_exists(pool, "kcc20_activity_feed").await? {
        let feed_has_rows: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kcc20_activity_feed LIMIT 1)")
                .fetch_one(pool)
                .await?;
        if feed_has_rows {
            let mut query = QueryBuilder::<Postgres>::new(
                r#"
                WITH selected AS (
                SELECT
                    id,
                    event_id,
                    token_id,
                    txid,
                    block_time_ms,
                    entrypoint,
                    kind,
                    side,
                    order_id,
                    owner_identifier,
                    owner_identifier_type,
                    owner_identifier_type_version,
                    token_amount,
                    unit_price_sompi,
                    price_sompi
                FROM kcc20_activity_feed
                WHERE token_id = "#,
            );
            query.push_bind(&activity_token_id);
            if let Some(kind) = normalized_filters.kind.as_deref() {
                query.push(" AND kind = ");
                query.push_bind(kind);
            }
            match normalized_filters.scope.as_deref() {
                Some("trading") => {
                    query.push(" AND kind IN ('orderCreated', 'orderCancelled', 'trade')");
                }
                Some("token") => {
                    query.push(" AND kind NOT IN ('orderCreated', 'orderCancelled', 'trade')");
                }
                _ => {}
            }
            if let Some(side) = normalized_filters.side.as_deref() {
                query.push(" AND side = ");
                query.push_bind(side);
            }
            if let Some(entrypoint) = normalized_filters.entrypoint.as_deref() {
                query.push(" AND entrypoint = ");
                query.push_bind(entrypoint);
            }
            if let Some(owner) = normalized_filters.owner.as_deref() {
                query.push(" AND lower(owner_identifier) = ");
                query.push_bind(owner);
            }
            if let Some(txid) = normalized_filters.txid.as_deref() {
                query.push(" AND txid = decode(");
                query.push_bind(txid);
                query.push(", 'hex')");
            }
            if let Some(order_id) = normalized_filters.order_id.as_deref() {
                query.push(" AND lower(order_id) = ");
                query.push_bind(order_id);
            }
            if let Some(from_ms) = normalized_filters.from_ms {
                query.push(" AND block_time_ms >= ");
                query.push_bind(from_ms);
            }
            if let Some(to_ms) = normalized_filters.to_ms {
                query.push(" AND block_time_ms < ");
                query.push_bind(to_ms);
            }
            query.push(" ORDER BY block_time_ms DESC, txid DESC, event_id DESC NULLS LAST, id DESC LIMIT ");
            query.push_bind(limit);
            query.push(" OFFSET ");
            query.push_bind(offset);
            query.push(
                r#"
                )
                SELECT
                    event_id,
                    encode(token_id, 'hex') AS token_id_hex,
                    encode(txid, 'hex') AS txid_hex,
                    block_time_ms,
                    entrypoint,
                    kind,
                    side,
                    order_id,
                    owner_identifier AS owner,
                    CASE
                        WHEN owner_identifier_type_version = 1
                            THEN owner_identifier_type
                        ELSE resolved.identifier_type
                    END AS owner_identifier_type,
                    token_amount,
                    unit_price_sompi,
                    price_sompi
                FROM selected
                LEFT JOIN LATERAL (
                    SELECT CASE
                        WHEN selected.owner_identifier IS NULL THEN NULL::SMALLINT
                        WHEN COUNT(candidate.owner_identifier) > 0
                         AND COUNT(candidate.identifier_type) =
                             COUNT(candidate.owner_identifier)
                         AND COUNT(DISTINCT candidate.identifier_type) = 1
                            THEN MIN(candidate.identifier_type)
                        ELSE NULL::SMALLINT
                    END AS identifier_type
                    FROM covenant_actions action
                    LEFT JOIN LATERAL (
                        SELECT source.owner_identifier, value.identifier_type
                        FROM (
                            VALUES
                                (
                                    action.outputs->'state'->>'ownerIdentifier',
                                    action.outputs->'state'->>'identifierType'
                                ),
                                (
                                    action.decoded_args->>'ownerIdentifier',
                                    action.decoded_args->>'identifierType'
                                ),
                                (
                                    action.decoded_args->>'stateOwner',
                                    action.decoded_args->>'stateOwnerType'
                                ),
                                (action.decoded_args->>'owner', '0'),
                                (action.decoded_args->>'wrappedRecipient', '0'),
                                (action.decoded_args->>'seller', '0'),
                                (action.decoded_args->>'buyer', '0'),
                                (action.decoded_args->>'ticketOwner', '0'),
                                (
                                    action.decoded_args->>'toOwner',
                                    action.decoded_args->>'toOwnerType'
                                ),
                                (
                                    action.decoded_args->>'tokenRecipient',
                                    action.decoded_args->>'tokenRecipientScheme'
                                )
                        ) AS source(owner_identifier, raw_identifier_type)
                        CROSS JOIN LATERAL (
                            SELECT CASE
                                WHEN source.raw_identifier_type ~ '^[012]$'
                                    THEN source.raw_identifier_type::SMALLINT
                                ELSE NULL::SMALLINT
                            END AS identifier_type
                        ) value
                        WHERE lower(source.owner_identifier) = lower(selected.owner_identifier)
                    ) candidate ON TRUE
                    WHERE action.txid = selected.txid
                ) resolved ON selected.owner_identifier_type_version <> 1
                ORDER BY block_time_ms DESC, txid DESC, event_id DESC NULLS LAST, id DESC
                "#,
            );
            let mut read_tx = pool.begin().await?;
            set_local_query_limits(
                &mut read_tx,
                API_READ_LOCK_TIMEOUT,
                KCC20_ACTIVITY_READ_STATEMENT_TIMEOUT,
            )
            .await?;
            let rows = match query.build().fetch_all(&mut *read_tx).await {
                Ok(rows) => {
                    read_tx.commit().await?;
                    rows
                }
                Err(error)
                    if error.to_string().contains("statement timeout")
                        || error
                            .to_string()
                            .contains("canceling statement due to statement timeout") =>
                {
                    let _ = read_tx.rollback().await;
                    tracing::warn!(
                        target: "kcc20_projector",
                        token_id_hex = %activity_token_id_hex,
                        error = %error,
                        "KCC20 activity owner-type hydration timed out; serving projected rows without hydration"
                    );
                    kcc20_activity_feed_rows_without_owner_hydration(
                        pool,
                        &activity_token_id,
                        &normalized_filters,
                        limit,
                        offset,
                    )
                    .await?
                }
                Err(error) => return Err(error.into()),
            };

            return Ok(rows.into_iter().map(kcc20_activity_row_from_pg).collect());
        }

        return Ok(Vec::new());
    }

    kcc20_activity_raw(
        pool,
        &activity_token_id_hex,
        &normalized_filters,
        limit,
        offset,
    )
    .await
}

fn kcc20_activity_row_from_pg(r: PgRow) -> Kcc20ActivityRow {
    Kcc20ActivityRow {
        event_id: r.get("event_id"),
        token_id_hex: r.get("token_id_hex"),
        txid_hex: r.get("txid_hex"),
        block_time_ms: r.get("block_time_ms"),
        kind: r.get("kind"),
        side: r.get("side"),
        order_id: r.get("order_id"),
        owner: r.get("owner"),
        owner_identifier_type: r.get("owner_identifier_type"),
        token_amount: r.get("token_amount"),
        unit_price_sompi: r.get("unit_price_sompi"),
        price_sompi: r.get("price_sompi"),
        entrypoint: r.get("entrypoint"),
    }
}

async fn kcc20_activity_feed_rows_without_owner_hydration(
    pool: &PgPool,
    activity_token_id: &[u8],
    filters: &Kcc20ActivityFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<PgRow>> {
    let mut query = QueryBuilder::<Postgres>::new(
        r#"
        SELECT
            event_id,
            encode(token_id, 'hex') AS token_id_hex,
            encode(txid, 'hex') AS txid_hex,
            block_time_ms,
            entrypoint,
            kind,
            side,
            order_id,
            owner_identifier AS owner,
            owner_identifier_type,
            token_amount,
            unit_price_sompi,
            price_sompi
        FROM kcc20_activity_feed
        WHERE token_id = "#,
    );
    query.push_bind(activity_token_id);
    if let Some(kind) = filters.kind.as_deref() {
        query.push(" AND kind = ");
        query.push_bind(kind);
    }
    match filters.scope.as_deref() {
        Some("trading") => {
            query.push(" AND kind IN ('orderCreated', 'orderCancelled', 'trade')");
        }
        Some("token") => {
            query.push(" AND kind NOT IN ('orderCreated', 'orderCancelled', 'trade')");
        }
        _ => {}
    }
    if let Some(side) = filters.side.as_deref() {
        query.push(" AND side = ");
        query.push_bind(side);
    }
    if let Some(entrypoint) = filters.entrypoint.as_deref() {
        query.push(" AND entrypoint = ");
        query.push_bind(entrypoint);
    }
    if let Some(owner) = filters.owner.as_deref() {
        query.push(" AND lower(owner_identifier) = ");
        query.push_bind(owner);
    }
    if let Some(txid) = filters.txid.as_deref() {
        query.push(" AND txid = decode(");
        query.push_bind(txid);
        query.push(", 'hex')");
    }
    if let Some(order_id) = filters.order_id.as_deref() {
        query.push(" AND lower(order_id) = ");
        query.push_bind(order_id);
    }
    if let Some(from_ms) = filters.from_ms {
        query.push(" AND block_time_ms >= ");
        query.push_bind(from_ms);
    }
    if let Some(to_ms) = filters.to_ms {
        query.push(" AND block_time_ms < ");
        query.push_bind(to_ms);
    }
    query.push(" ORDER BY block_time_ms DESC, txid DESC, event_id DESC NULLS LAST, id DESC LIMIT ");
    query.push_bind(limit);
    query.push(" OFFSET ");
    query.push_bind(offset);

    let mut read_tx = pool.begin().await?;
    set_local_query_limits(
        &mut read_tx,
        API_READ_LOCK_TIMEOUT,
        KCC20_ACTIVITY_READ_STATEMENT_TIMEOUT,
    )
    .await?;
    let rows = query.build().fetch_all(&mut *read_tx).await?;
    read_tx.commit().await?;
    Ok(rows)
}

async fn kcc20_activity_raw(
    pool: &PgPool,
    token_id_hex: &str,
    filters: &Kcc20ActivityFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20ActivityRow>> {
    kcc20_activity_raw_scoped(pool, token_id_hex, filters, limit, offset, None).await
}

async fn kcc20_activity_raw_scoped(
    pool: &PgPool,
    token_id_hex: &str,
    filters: &Kcc20ActivityFilter,
    limit: i64,
    offset: i64,
    txid_hexes: Option<&[String]>,
) -> Result<Vec<Kcc20ActivityRow>> {
    let rows = sqlx::query(AssertSqlSafe(kcc20_trade_sql(
        r#"
        WITH activity AS (
            SELECT
                kcc20_activity_event_id(a.txid, a.action, a.inputs, a.outputs) AS event_id,
                COALESCE(
                    encode(a.canonical_token_id, 'hex'),
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(order_out.outputs->'state'->>'canonicalTokenId', ''),
                    NULLIF(a.decoded_args->>'utilityTokenId', ''),
                    NULLIF(order_out.outputs->'state'->>'utilityTokenId', ''),
                    NULLIF(holder_out.outputs->'state'->>'utilityTokenId', ''),
                    NULLIF(holder_out.outputs->'state'->>'canonicalTokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id_hex,
                encode(a.txid, 'hex')        AS txid_hex,
                a.block_time_ms              AS block_time_ms,
                a.id                         AS activity_source_id,
                COALESCE(a.entrypoint, parent_spend.entrypoint) AS entrypoint,
                CASE
                    WHEN a.action = 'deploy' THEN 'deploy'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('createAskByOwnerSig') THEN 'orderCreated'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('createBidFromRoot') THEN 'orderCreated'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig') THEN 'orderCancelled'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide') THEN 'trade'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'mergeByOwnerSig' THEN 'consolidate'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('mint_by_owner', 'mint_public') THEN 'mint'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'set_public_mint_active' THEN 'mintConfig'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('transfer', 'transfer_delegator') THEN 'transfer'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'burnByOwnerSig'
                     AND COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket' THEN 'feeTicketBurn'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'burn' THEN 'burn'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'wrap' THEN 'wrap'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('unwrap', 'unwrapByOwnerSig') THEN 'unwrap'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'createFromUtilityBurn' THEN 'feeTicketCreate'
                    WHEN COALESCE(a.entrypoint, parent_spend.entrypoint) = 'updateDenominationByOwnerSig' THEN 'feeTicketConfig'
                    ELSE 'action'
                END AS kind,
                CASE
                    WHEN a.entrypoint IN ('createAskByOwnerSig', 'fillAskPartial', 'crossAskSide', 'cancelAskByOwnerSig') THEN 'ask'
                    WHEN a.entrypoint IN ('createBidFromRoot', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossBidSide', 'cancelBidByOwnerSig') THEN 'bid'
                    ELSE NULL
                END AS side,
                CASE
                    WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                     AND a.inputs->'previousOutpoint'->>'hash' IS NOT NULL
                        THEN (a.inputs->'previousOutpoint'->>'hash') || ':' || (a.inputs->'previousOutpoint'->>'index')
                    WHEN order_out.outputs->>'vout' IS NOT NULL THEN encode(a.txid, 'hex') || ':' || (order_out.outputs->>'vout')
                    WHEN a.inputs->'previousOutpoint'->>'hash' IS NOT NULL THEN (a.inputs->'previousOutpoint'->>'hash') || ':' || (a.inputs->'previousOutpoint'->>'index')
                    ELSE NULL
                END AS order_id,
                CASE
                    WHEN a.entrypoint = 'wrap' THEN COALESCE(
                        NULLIF(a.decoded_args->>'wrappedRecipient', ''),
                        lifecycle_out.owner_identifier,
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner'
                    )
                    WHEN a.entrypoint = 'unwrap' THEN COALESCE(
                        NULLIF(a.decoded_args->>'tokenRecipient', ''),
                        lifecycle_out.owner_identifier,
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner',
                        holder_out.outputs->'state'->>'ownerIdentifier'
                    )
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide') THEN COALESCE(
                        NULLIF(seller_spend.decoded_args->>'ownerIdentifier', ''),
                        NULLIF(a.decoded_args->>'seller', ''),
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier'
                    )
                    ELSE COALESCE(
                        holder_out.outputs->'state'->>'owner',
                        holder_out.outputs->'state'->>'ownerIdentifier',
                        order_out.outputs->'state'->>'ownerIdentifier',
                        a.outputs->'state'->>'owner',
                        a.outputs->'state'->>'ownerIdentifier',
                        a.decoded_args->>'ownerIdentifier',
                        a.decoded_args->>'stateOwner',
                        a.decoded_args->>'owner',
                        a.decoded_args->>'seller',
                        a.decoded_args->>'buyer',
                        a.decoded_args->>'ticketOwner',
                        a.decoded_args->>'toOwner',
                        a.decoded_args->>'tokenRecipient'
                    )
                END AS owner,
                CASE
                    WHEN a.entrypoint = 'wrap' THEN CASE
                        WHEN NULLIF(a.decoded_args->>'wrappedRecipient', '') IS NOT NULL
                            THEN 0::SMALLINT
                        WHEN lifecycle_out.owner_identifier IS NOT NULL THEN CASE
                            WHEN lifecycle_out.owner_identifier_type ~ '^[012]$'
                                THEN lifecycle_out.owner_identifier_type::SMALLINT
                            ELSE NULL
                        END
                        WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                                THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (a.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                                THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                            ELSE NULL
                        END
                        ELSE NULL
                    END
                    WHEN a.entrypoint = 'unwrap' THEN CASE
                        WHEN NULLIF(a.decoded_args->>'tokenRecipient', '') IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'tokenRecipientScheme' ~ '^[012]$'
                                THEN (a.decoded_args->>'tokenRecipientScheme')::SMALLINT
                            ELSE NULL
                        END
                        WHEN lifecycle_out.owner_identifier IS NOT NULL THEN CASE
                            WHEN lifecycle_out.owner_identifier_type ~ '^[012]$'
                                THEN lifecycle_out.owner_identifier_type::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (a.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                            WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                                THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                            ELSE NULL
                        END
                        WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                            WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                                THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                            ELSE NULL
                        END
                        ELSE NULL
                    END
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'crossBidSide')
                     AND (
                        NULLIF(seller_spend.decoded_args->>'ownerIdentifier', '') IS NOT NULL
                        OR NULLIF(a.decoded_args->>'seller', '') IS NOT NULL
                     ) THEN COALESCE(
                        CASE
                            WHEN seller_spend.decoded_args->>'identifierType' ~ '^[012]$'
                                THEN (seller_spend.decoded_args->>'identifierType')::SMALLINT
                            ELSE NULL
                        END,
                        0::SMALLINT
                    )
                    WHEN holder_out.outputs->'state'->>'owner' IS NOT NULL THEN CASE
                        WHEN holder_out.outputs->'state'->>'ownerScheme' ~ '^[0-4]$'
                            THEN (holder_out.outputs->'state'->>'ownerScheme')::SMALLINT
                        ELSE NULL
                    END
                    WHEN holder_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN holder_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (holder_out.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN order_out.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN order_out.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (order_out.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.outputs->'state'->>'owner' IS NOT NULL THEN CASE
                        WHEN a.outputs->'state'->>'ownerScheme' ~ '^[0-4]$'
                            THEN (a.outputs->'state'->>'ownerScheme')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.outputs->'state'->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN a.outputs->'state'->>'identifierType' ~ '^[012]$'
                            THEN (a.outputs->'state'->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'ownerIdentifier' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'identifierType' ~ '^[012]$'
                            THEN (a.decoded_args->>'identifierType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'stateOwner' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'stateOwnerType' ~ '^[012]$'
                            THEN (a.decoded_args->>'stateOwnerType')::SMALLINT
                        ELSE NULL
                    END
                    -- These legacy fields are fixed 32-byte x-only public keys
                    -- in their decoder schemas and have no sibling type field.
                    WHEN a.decoded_args->>'owner' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'seller' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'buyer' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'ticketOwner' IS NOT NULL THEN 0::SMALLINT
                    WHEN a.decoded_args->>'toOwner' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'toOwnerType' ~ '^[012]$'
                            THEN (a.decoded_args->>'toOwnerType')::SMALLINT
                        ELSE NULL
                    END
                    WHEN a.decoded_args->>'tokenRecipient' IS NOT NULL THEN CASE
                        WHEN a.decoded_args->>'tokenRecipientScheme' ~ '^[012]$'
                            THEN (a.decoded_args->>'tokenRecipientScheme')::SMALLINT
                        ELSE NULL
                    END
                    ELSE NULL
                END AS owner_identifier_type,
                activity_values.token_amount AS token_amount,
                activity_values.unit_price_sompi AS unit_price_sompi,
                CASE
                    WHEN activity_values.token_amount ~ '^[0-9]+$'
                     AND activity_values.unit_price_sompi ~ '^[0-9]+$'
                    THEN FLOOR(
                        activity_values.token_amount::NUMERIC
                        * activity_values.unit_price_sompi::NUMERIC
                        / GREATEST(COALESCE(NULLIF(holder_out.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(order_out.outputs->'state'->>'priceScale', '')::NUMERIC, NULLIF(a.decoded_args->>'priceScale', '')::NUMERIC, 1), 1)
                    )::TEXT
                    ELSE NULL
                END AS price_sompi
            FROM covenant_actions a
            JOIN covenants c ON c.covenant_id = a.covenant_id
            LEFT JOIN LATERAL (
                SELECT spend.entrypoint
                FROM covenant_actions spend
                JOIN covenants spend_c ON spend_c.covenant_id = spend.covenant_id
                WHERE spend.txid = a.txid
                  AND spend.action = 'spend'
                  AND spend.entrypoint IS NOT NULL
                  AND (
                    spend.covenant_id = a.covenant_id
                    OR (
                        COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                        AND COALESCE(spend_c.template_name, spend_c.claimed_template) = 'KCC20'
                        AND COALESCE(spend.canonical_token_id, spend.covenant_id)
                            = COALESCE(a.canonical_token_id, a.covenant_id)
                    )
                  )
                ORDER BY
                  CASE
                    WHEN a.action = 'continuation'
                     AND a.outputs->>'vout' IN (
                       spend.decoded_args->>'tokenOutputIndex',
                       spend.decoded_args->>'changeOutputIndex',
                       spend.decoded_args->>'minterOutputIndex',
                       spend.decoded_args->>'mergedOutputIndex'
                     ) THEN 0
                    WHEN NOT (
                       spend.decoded_args ? 'tokenOutputIndex'
                       OR spend.decoded_args ? 'changeOutputIndex'
                       OR spend.decoded_args ? 'minterOutputIndex'
                       OR spend.decoded_args ? 'mergedOutputIndex'
                    ) THEN 1
                    ELSE 2
                  END,
                  CASE WHEN spend.covenant_id = a.covenant_id THEN 0 ELSE 1 END,
                  spend.id ASC
                LIMIT 1
            ) parent_spend ON TRUE
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions cont
                WHERE cont.covenant_id = a.covenant_id
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->'state'->>'mode' IN ('2', '3')
                  AND (
                      COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) IS NULL
                      OR cont.outputs->>'vout' = COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', ''))
                  )
                ORDER BY
                  CASE
                      WHEN COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) IS NOT NULL
                       AND cont.outputs->>'vout' = COALESCE(NULLIF(a.decoded_args->>'askOutputIndex', ''), NULLIF(a.decoded_args->>'bidOutputIndex', '')) THEN 0
                      ELSE 1
                  END,
                  (cont.outputs ? 'vout') DESC,
                  cont.id DESC
                LIMIT 1
            ) order_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT outputs
                FROM covenant_actions cont
                WHERE cont.covenant_id = a.covenant_id
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->'state'->>'mode' = '0'
                  AND (
                      NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NULL
                      OR cont.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex'
                  )
                ORDER BY
                  CASE
                      WHEN NULLIF(a.decoded_args->>'buyerOutputIndex', '') IS NOT NULL
                       AND cont.outputs->>'vout' = a.decoded_args->>'buyerOutputIndex' THEN 0
                      ELSE 1
                  END,
                  (cont.outputs ? 'vout') DESC,
                  cont.id DESC
                LIMIT 1
            ) holder_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT
                    cont.outputs->'state'->>'ownerIdentifier' AS owner_identifier,
                    cont.outputs->'state'->>'identifierType' AS owner_identifier_type
                FROM covenant_actions cont
                WHERE a.entrypoint IN ('wrap', 'unwrap')
                  AND cont.txid = a.txid
                  AND cont.action = 'continuation'
                  AND cont.outputs->>'vout' = CASE
                      WHEN a.entrypoint = 'wrap'
                          THEN a.decoded_args->>'orderbookHolderOutputIndex'
                      WHEN a.entrypoint = 'unwrap'
                          THEN a.decoded_args->>'tokenRecipientOutputIndex'
                      ELSE NULL
                  END
                  AND lower(COALESCE(
                        encode(cont.canonical_token_id, 'hex'),
                        NULLIF(cont.outputs->'state'->>'canonicalTokenId', ''),
                        encode(cont.covenant_id, 'hex')
                      )) = lower(COALESCE(
                        encode(a.canonical_token_id, 'hex'),
                        NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                        encode(a.covenant_id, 'hex')
                      ))
                ORDER BY cont.id DESC
                LIMIT 1
            ) lifecycle_out ON TRUE
            LEFT JOIN LATERAL (
                SELECT decoded_args
                FROM covenant_actions seller_spend
                WHERE seller_spend.covenant_id = a.covenant_id
                  AND seller_spend.txid = a.txid
                  AND seller_spend.action = 'spend'
                  AND NULLIF(a.decoded_args->>'sellerInputIndex', '') IS NOT NULL
                  AND seller_spend.decoded_args->>'inputIndex' = a.decoded_args->>'sellerInputIndex'
                ORDER BY seller_spend.id ASC
                LIMIT 1
            ) seller_spend ON TRUE
            CROSS JOIN LATERAL (
                SELECT
                    CASE
                        WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                            THEN COALESCE(NULLIF(a.decoded_args->>'fillAmount', ''), holder_out.outputs->'state'->>'amount')
                        WHEN a.entrypoint IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig')
                            THEN a.decoded_args->>'amount'
                        WHEN a.entrypoint = 'wrap'
                            THEN NULLIF(a.decoded_args->>'tokenAmount', '')
                        WHEN a.entrypoint = 'unwrap'
                            THEN NULLIF(a.decoded_args->>'tokenAmount', '')
                        WHEN a.entrypoint = 'unwrapByOwnerSig'
                            THEN COALESCE(
                                NULLIF(a.decoded_args->>'tokenAmount', ''),
                                NULLIF(a.decoded_args->>'amount', ''),
                                NULLIF(a.decoded_args->>'stateAmount', '')
                            )
                        WHEN a.entrypoint = 'burn'
                            THEN NULLIF(a.decoded_args->>'burnAmount', '')
                        ELSE COALESCE(
                            order_out.outputs->'state'->>'amount',
                            holder_out.outputs->'state'->>'amount',
                            a.outputs->'state'->>'amount',
                            a.decoded_args->>'amount',
                            a.decoded_args->>'tokenAmount',
                            a.decoded_args->>'denomination',
                            a.outputs->'state'->>'denomination'
                        )
                    END AS token_amount,
                    CASE
                        WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide')
                            THEN a.decoded_args->>'unitPriceSompi'
                        WHEN a.entrypoint IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig')
                            THEN a.decoded_args->>'unitPriceSompi'
                        ELSE COALESCE(order_out.outputs->'state'->>'unitPriceSompi', a.decoded_args->>'unitPriceSompi')
                    END AS unit_price_sompi
            ) activity_values
            WHERE (
                COALESCE(c.template_name, c.claimed_template) IN ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')
                OR (
                    a.canonical_token_id IS NOT NULL
                    AND a.action IN ('deploy', 'continuation')
                    AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                    AND a.outputs->'state' ? 'ticker'
                    AND a.outputs->'state' ? 'tokenName'
                )
              )
              AND (
                (
                    (
                        COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                        OR (
                            a.canonical_token_id IS NOT NULL
                            AND a.action IN ('deploy', 'continuation')
                            AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                            AND a.outputs->'state' ? 'ticker'
                            AND a.outputs->'state' ? 'tokenName'
                        )
                    )
                    AND (
                        a.action = 'deploy'
                        OR (
                            a.action = 'continuation'
                            AND COALESCE(parent_spend.entrypoint, '') <> 'burn'
                        )
                        OR (a.action = 'spend' AND a.entrypoint = 'burn')
                    )
                )
                OR (
                    a.action = 'spend'
                    AND (
                        (
                            COALESCE(c.template_name, c.claimed_template) IN ('KCC20Orderbook', 'KCC20Wrapper')
                            AND a.entrypoint IN (
                                'createAskByOwnerSig', 'createBidFromRoot',
                                'fillAskPartial', 'fillBidPartial',
                                'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig',
                                'crossAskSide', 'crossBidSide',
                                'cancelAskByOwnerSig', 'cancelBidByOwnerSig',
                                'unwrapByOwnerSig', 'mergeByOwnerSig'
                            )
                        )
                        OR (
                            (c.template_name = 'KCC20Wrapper'
                             OR c.claimed_template = 'KCC20Wrapper')
                            AND a.entrypoint IN ('wrap', 'unwrap')
                        )
                        OR (
                            COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                            AND a.entrypoint IN (
                                'createFromUtilityBurn',
                                'transferByOwnerSig',
                                'burnByOwnerSig',
                                'updateDenominationByOwnerSig'
                            )
                        )
                    )
                )
              )
              AND NOT (
                a.action = 'spend'
                AND a.entrypoint = 'sellIntoBidByOwnerSig'
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions bid_fill
                  WHERE bid_fill.txid = a.txid
                    AND bid_fill.covenant_id = a.covenant_id
                    AND bid_fill.action = 'spend'
                    AND bid_fill.entrypoint = 'fillBidPartial'
                    AND NULLIF(bid_fill.decoded_args->>'buyerOutputIndex', '') = NULLIF(a.decoded_args->>'buyerOutputIndex', '')
                    AND NULLIF(bid_fill.decoded_args->>'fillAmount', '') = NULLIF(a.decoded_args->>'fillAmount', '')
                  )
              )
              __KCC20_CROSS_MATCH_DEDUPE_GUARD__
              AND NOT (
                a.action = 'spend'
                AND a.entrypoint IN ('wrap', 'unwrap')
                AND a.inputs->'previousOutpoint'->>'hash' IS NOT NULL
                AND a.inputs->'previousOutpoint'->>'index' IS NOT NULL
                AND EXISTS (
                  SELECT 1
                  FROM covenant_actions duplicate_lifecycle
                  JOIN covenants duplicate_c
                    ON duplicate_c.covenant_id = duplicate_lifecycle.covenant_id
                  WHERE duplicate_lifecycle.txid = a.txid
                    AND duplicate_lifecycle.action = 'spend'
                    AND duplicate_lifecycle.entrypoint = a.entrypoint
                    AND duplicate_lifecycle.id > a.id
                    AND lower(duplicate_lifecycle.inputs->'previousOutpoint'->>'hash')
                        = lower(a.inputs->'previousOutpoint'->>'hash')
                    AND duplicate_lifecycle.inputs->'previousOutpoint'->>'index'
                        = a.inputs->'previousOutpoint'->>'index'
                    AND COALESCE(
                          duplicate_c.template_name,
                          duplicate_c.claimed_template
                        ) = 'KCC20Wrapper'
                    AND lower(COALESCE(
                          encode(duplicate_lifecycle.canonical_token_id, 'hex'),
                          NULLIF(
                            duplicate_lifecycle.decoded_args->>'canonicalTokenId',
                            ''
                          ),
                          encode(duplicate_lifecycle.covenant_id, 'hex')
                        )) = lower(COALESCE(
                          encode(a.canonical_token_id, 'hex'),
                          NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                          encode(a.covenant_id, 'hex')
                        ))
                )
              )
              AND NOT (
                COALESCE(a.entrypoint, parent_spend.entrypoint) IN ('mint_by_owner', 'mint_public')
                AND a.action = 'continuation'
                AND COALESCE(
                    a.outputs->'state'->>'isMintAuthority',
                    a.outputs->'state'->>'isMinter',
                    'false'
                ) = 'true'
              )
              AND NOT (
                (
                    (
                        a.action = 'continuation'
                        AND (
                            COALESCE(c.template_name, c.claimed_template) = 'KCC20'
                            OR (
                                a.canonical_token_id IS NOT NULL
                                AND COALESCE(a.outputs->'state'->>'mintPricePerTokenSompi', a.outputs->'state'->>'mintPriceSompi') IS NOT NULL
                                AND a.outputs->'state' ? 'ticker'
                                AND a.outputs->'state' ? 'tokenName'
                            )
                        )
                    )
                    OR (
                        a.action = 'spend'
                        AND COALESCE(c.template_name, c.claimed_template) IN (
                          'KCC20Orderbook', 'KCC20Wrapper'
                        )
                        AND a.entrypoint = 'unwrapByOwnerSig'
                    )
                )
                AND EXISTS (
                    SELECT 1
                    FROM covenant_actions wrapper_action
                    JOIN covenants wrapper_c
                      ON wrapper_c.covenant_id = wrapper_action.covenant_id
                    WHERE wrapper_action.txid = a.txid
                      AND wrapper_action.action = 'spend'
                      AND wrapper_action.entrypoint IN ('wrap', 'unwrap')
                      AND (wrapper_c.template_name = 'KCC20Wrapper'
                           OR wrapper_c.claimed_template = 'KCC20Wrapper')
                      AND lower(COALESCE(
                            encode(wrapper_action.canonical_token_id, 'hex'),
                            NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                          )) = lower(COALESCE(
                            encode(a.canonical_token_id, 'hex'),
                            NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                            NULLIF(order_out.outputs->'state'->>'canonicalTokenId', ''),
                            NULLIF(a.decoded_args->>'utilityTokenId', ''),
                            NULLIF(order_out.outputs->'state'->>'utilityTokenId', ''),
                            NULLIF(holder_out.outputs->'state'->>'utilityTokenId', ''),
                            NULLIF(holder_out.outputs->'state'->>'canonicalTokenId', ''),
                            encode(a.covenant_id, 'hex')
                          ))
                      AND (
                        (
                          a.action = 'spend'
                          AND (
                            (
                              wrapper_action.covenant_id = a.covenant_id
                              AND wrapper_action.decoded_args->>'wrappedInputIndex' IS NOT NULL
                              AND a.decoded_args->>'inputIndex' = wrapper_action.decoded_args->>'wrappedInputIndex'
                            )
                            OR (
                              wrapper_action.covenant_id = a.covenant_id
                              AND
                              wrapper_action.decoded_args->>'wrappedInputIndex' IS NULL
                              AND 1 = (
                                SELECT COUNT(*)
                                FROM covenant_actions wrapped_spend
                                WHERE wrapped_spend.txid = a.txid
                                  AND wrapped_spend.action = 'spend'
                                  AND wrapped_spend.entrypoint = 'unwrapByOwnerSig'
                                  AND lower(COALESCE(
                                        encode(wrapped_spend.canonical_token_id, 'hex'),
                                        NULLIF(wrapped_spend.decoded_args->>'canonicalTokenId', '')
                                      )) = lower(COALESCE(
                                        encode(wrapper_action.canonical_token_id, 'hex'),
                                        NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                      ))
                              )
                            )
                          )
                        )
                        OR (
                          a.action = 'continuation'
                          AND (
                            EXISTS (
                              SELECT 1
                              FROM covenant_actions token_spend
                              JOIN covenants token_c
                                ON token_c.covenant_id = token_spend.covenant_id
                              WHERE token_spend.txid = a.txid
                                AND token_spend.action = 'spend'
                                AND COALESCE(token_c.template_name, token_c.claimed_template) = 'KCC20'
                                AND lower(COALESCE(
                                      encode(token_spend.canonical_token_id, 'hex'),
                                      encode(token_spend.covenant_id, 'hex')
                                    )) = lower(COALESCE(
                                      encode(wrapper_action.canonical_token_id, 'hex'),
                                      NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                    ))
                                AND a.outputs->>'vout' IN (
                                  token_spend.decoded_args->>'tokenOutputIndex',
                                  token_spend.decoded_args->>'changeOutputIndex'
                                )
                                AND (
                                  (
                                    token_spend.decoded_args->>'inputIndex' IS NOT NULL
                                    AND CASE
                                      WHEN wrapper_action.entrypoint = 'wrap'
                                        THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                      WHEN wrapper_action.entrypoint = 'unwrap'
                                        THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                      ELSE NULL
                                    END IS NOT NULL
                                    AND token_spend.decoded_args->>'inputIndex' = CASE
                                      WHEN wrapper_action.entrypoint = 'wrap'
                                        THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                      WHEN wrapper_action.entrypoint = 'unwrap'
                                        THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                      ELSE NULL
                                    END
                                  )
                                  OR (
                                    (
                                      token_spend.decoded_args->>'inputIndex' IS NULL
                                      OR CASE
                                        WHEN wrapper_action.entrypoint = 'wrap'
                                          THEN wrapper_action.decoded_args->>'tokenInputIndex'
                                        WHEN wrapper_action.entrypoint = 'unwrap'
                                          THEN wrapper_action.decoded_args->>'tokenReserveInputIndex'
                                        ELSE NULL
                                      END IS NULL
                                    )
                                    AND 1 = (
                                      SELECT COUNT(*)
                                      FROM covenant_actions legacy_token_spend
                                      JOIN covenants legacy_token_c
                                        ON legacy_token_c.covenant_id = legacy_token_spend.covenant_id
                                      WHERE legacy_token_spend.txid = a.txid
                                        AND legacy_token_spend.action = 'spend'
                                        AND COALESCE(
                                          legacy_token_c.template_name,
                                          legacy_token_c.claimed_template
                                        ) = 'KCC20'
                                        AND lower(COALESCE(
                                              encode(legacy_token_spend.canonical_token_id, 'hex'),
                                              encode(legacy_token_spend.covenant_id, 'hex')
                                            )) = lower(COALESCE(
                                              encode(wrapper_action.canonical_token_id, 'hex'),
                                              NULLIF(
                                                wrapper_action.decoded_args->>'canonicalTokenId',
                                                ''
                                              )
                                            ))
                                    )
                                  )
                                )
                            )
                            OR
                            (
                              wrapper_action.entrypoint = 'wrap'
                              AND a.outputs->>'vout' IN (
                                wrapper_action.decoded_args->>'tokenLockedOutputIndex',
                                wrapper_action.decoded_args->>'orderbookHolderOutputIndex',
                                wrapper_action.decoded_args->>'wrapperOutputIndex'
                              )
                            )
                            OR (
                              wrapper_action.entrypoint = 'unwrap'
                              AND wrapper_action.decoded_args ? 'tokenRecipientOutputIndex'
                              AND a.outputs->>'vout' IN (
                                wrapper_action.decoded_args->>'tokenRecipientOutputIndex',
                                wrapper_action.decoded_args->>'tokenReserveChangeOutputIndex',
                                wrapper_action.decoded_args->>'wrappedChangeOutputIndex',
                                wrapper_action.decoded_args->>'wrapperOutputIndex'
                              )
                            )
                            OR (
                              NOT (
                                wrapper_action.decoded_args ? 'tokenLockedOutputIndex'
                                OR wrapper_action.decoded_args ? 'tokenRecipientOutputIndex'
                                OR wrapper_action.decoded_args ? 'orderbookHolderOutputIndex'
                                OR wrapper_action.decoded_args ? 'wrappedChangeOutputIndex'
                              )
                              AND 1 = (
                                SELECT COUNT(*)
                                FROM covenant_actions token_spend
                                JOIN covenants token_c
                                  ON token_c.covenant_id = token_spend.covenant_id
                                WHERE token_spend.txid = a.txid
                                  AND token_spend.action = 'spend'
                                  AND COALESCE(token_c.template_name, token_c.claimed_template) = 'KCC20'
                                  AND lower(COALESCE(
                                        encode(token_spend.canonical_token_id, 'hex'),
                                        encode(token_spend.covenant_id, 'hex')
                                      )) = lower(COALESCE(
                                        encode(wrapper_action.canonical_token_id, 'hex'),
                                        NULLIF(wrapper_action.decoded_args->>'canonicalTokenId', '')
                                      ))
                              )
                            )
                          )
                        )
                      )
                )
              )
            UNION ALL
            SELECT kcc20_activity_fill_event_id(txid, input_index),token_id_hex,txid_hex,block_time_ms,source_action_id,entrypoint,'trade',
                   CASE WHEN side='sell' THEN 'bid' ELSE 'ask' END,
                   order_id,taker,taker_scheme,token_amount,unit_price_sompi,price_sompi
            FROM kcc20_fee_trade_executions
        )
        SELECT *
        FROM activity
        WHERE token_id_hex = $1
          AND ($4::TEXT IS NULL OR kind = $4)
          AND ($5::TEXT IS NULL OR side = $5)
          AND ($6::TEXT IS NULL OR entrypoint = $6)
          AND ($7::TEXT IS NULL OR lower(owner) = $7)
          AND ($8::TEXT IS NULL OR txid_hex = lower($8))
          AND ($9::TEXT IS NULL OR lower(order_id) = $9)
          AND ($13::TEXT[] IS NULL OR txid_hex = ANY($13))
          AND (
              $10::TEXT IS NULL
              OR $10::TEXT = 'all'
              OR ($10::TEXT = 'trading' AND kind IN ('orderCreated', 'orderCancelled', 'trade'))
              OR ($10::TEXT = 'token' AND kind NOT IN ('orderCreated', 'orderCancelled', 'trade'))
          )
          AND ($11::BIGINT IS NULL OR block_time_ms >= $11)
          AND ($12::BIGINT IS NULL OR block_time_ms < $12)
        ORDER BY block_time_ms DESC, txid_hex DESC, event_id DESC NULLS LAST, activity_source_id DESC
        LIMIT $2 OFFSET $3
        "#,
        )))
    .bind(token_id_hex)
    .bind(limit)
    .bind(offset)
    .bind(filters.kind.as_deref())
    .bind(filters.side.as_deref())
    .bind(filters.entrypoint.as_deref())
    .bind(filters.owner.as_deref())
    .bind(filters.txid.as_deref())
    .bind(filters.order_id.as_deref())
    .bind(filters.scope.as_deref())
    .bind(filters.from_ms)
    .bind(filters.to_ms)
    .bind(txid_hexes.map(|values| values.to_vec()))
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(kcc20_activity_row_from_pg).collect())
}

/// KNOWN GAP: this function classifies `crossAskSide`/`crossBidSide` (and
/// `sellIntoBidByOwnerSig`/`fillBidPartial`) as `kind = 'trade'` below but,
/// unlike the 7 functions using [`KCC20_CROSS_MATCH_DEDUPE_GUARD`], applies
/// NO dedupe guard at all -- a per-owner action-history view can show 2 rows
/// for a trade that `kcc20_trades`/`kcc20_activity_raw`/etc. now correctly
/// report as 1. This is a raw per-wallet action list, not a volume
/// aggregate, so it's intentionally left out of the cross-match dedupe fix
/// as a separate, lower-priority follow-up rather than bundling an
/// unrelated behavior change into that fix.
const KCC20_OWNER_ACTION_SELECT_SQL: &str = r#"
            SELECT
                a.id AS action_id,
                a.txid AS txid_bytes,
                encode(c.covenant_id, 'hex') AS covenant_id_hex,
                COALESCE(c.template_name, c.claimed_template) AS template_name,
                encode(a.txid, 'hex') AS txid_hex,
                a.block_time_ms,
                a.entrypoint,
                a.action AS raw_action,
                a.inputs,
                a.outputs,
                a.decoded_args,
                output_state.state AS output_state,
                COALESCE(
                    output_state.state->>'ownerIdentifier',
                    output_state.state->>'stateOwner',
                    output_state.state->>'owner',
                    a.decoded_args->>'ownerIdentifier',
                    a.decoded_args->>'stateOwner',
                    a.decoded_args->>'owner',
                    a.decoded_args->>'seller',
                    a.decoded_args->>'listingSeller',
                    a.decoded_args->>'buyer',
                    a.decoded_args->>'orderBuyer',
                    a.decoded_args->>'wrappedRecipient',
                    a.decoded_args->>'ticketOwner',
                    a.decoded_args->>'toOwner',
                    a.decoded_args->>'tokenRecipient'
                ) AS owner,
                COALESCE(
                    encode(a.canonical_token_id, 'hex'),
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(output_state.state->>'canonicalTokenId', ''),
                    NULLIF(a.decoded_args->>'tokenId', ''),
                    NULLIF(a.decoded_args->>'listingTokenId', ''),
                    NULLIF(a.decoded_args->>'orderedTokenId', ''),
                    NULLIF(a.decoded_args->>'utilityTokenId', ''),
                    NULLIF(output_state.state->>'utilityTokenId', ''),
                    NULLIF(output_state.state->>'tokenId', ''),
                    encode(a.covenant_id, 'hex')
                ) AS token_id,
                COALESCE(
                    encode(a.canonical_token_id, 'hex'),
                    NULLIF(a.decoded_args->>'canonicalTokenId', ''),
                    NULLIF(output_state.state->>'canonicalTokenId', ''),
                    NULLIF(a.decoded_args->>'utilityTokenId', ''),
                    NULLIF(output_state.state->>'utilityTokenId', '')
                ) AS canonical_token_id,
                CASE
                    WHEN COALESCE(c.template_name, c.claimed_template) IN ('KCC20Orderbook', 'KCC20Wrapper')
                      OR a.decoded_args ? 'canonicalTokenId'
                      OR output_state.state ? 'canonicalTokenId'
                    THEN encode(a.covenant_id, 'hex')
                    ELSE NULL
                END AS wrapped_token_id,
                COALESCE(
                    output_state.state->>'amount',
                    a.decoded_args->>'amount',
                    a.decoded_args->>'tokenAmount',
                    a.decoded_args->>'listingTokenAmount',
                    a.decoded_args->>'orderedTokenAmount',
                    a.decoded_args->>'denomination',
                    output_state.state->>'denomination'
                ) AS amount,
                CASE
                    WHEN a.action = 'deploy' THEN 'deploy'
                    WHEN a.entrypoint IN ('mint_by_owner', 'mint_public', 'mintByAuthoritySig', 'mintPublic', 'issueFromRoot') THEN 'mint'
                    WHEN a.entrypoint = 'set_public_mint_active' THEN 'mintConfig'
                    WHEN a.entrypoint = 'wrap' THEN 'wrap'
                    WHEN a.entrypoint IN ('unwrap', 'unwrapByOwnerSig') THEN 'unwrap'
                    WHEN COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                     AND a.entrypoint = 'createFromUtilityBurn' THEN 'feeTicketCreate'
                    WHEN COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                     AND a.entrypoint = 'burnByOwnerSig' THEN 'feeTicketBurn'
                    WHEN COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                     AND a.entrypoint = 'transferByOwnerSig' THEN 'feeTicketUse'
                    WHEN COALESCE(c.template_name, c.claimed_template) = 'KCC20FeeTicket'
                     AND a.entrypoint = 'updateDenominationByOwnerSig' THEN 'feeTicketConfig'
                    WHEN a.entrypoint IN ('createAskByOwnerSig', 'createBidFromRoot') THEN 'orderCreate'
                    WHEN a.entrypoint IN ('cancelAskByOwnerSig', 'cancelBidByOwnerSig') THEN 'orderCancel'
                    WHEN a.entrypoint IN ('fillAskPartial', 'fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossAskSide', 'crossBidSide') THEN 'trade'
                    WHEN a.entrypoint = 'mergeByOwnerSig' THEN 'consolidate'
                    WHEN a.entrypoint IN ('burn', 'burnByOwnerSig') THEN 'burn'
                    WHEN a.entrypoint IS NOT NULL AND a.entrypoint LIKE 'transfer%' THEN 'transfer'
                    WHEN a.entrypoint = 'sellIntoBidByOwnerSig' THEN 'transfer'
                    ELSE COALESCE(a.entrypoint, a.action)
                END AS normalized_action,
                CASE
                    WHEN a.entrypoint IN ('mint_by_owner', 'mint_public', 'mintByAuthoritySig', 'mintPublic', 'issueFromRoot') THEN 'in'
                    WHEN a.entrypoint = 'wrap' THEN 'out'
                    WHEN a.entrypoint IN ('unwrap', 'unwrapByOwnerSig') THEN 'in'
                    WHEN a.entrypoint IN ('burn', 'burnByOwnerSig') THEN 'out'
                    WHEN a.entrypoint IN ('fillAskPartial', 'crossAskSide') THEN 'in'
                    WHEN a.entrypoint IN ('fillBidPartial', 'fillBidFromSellerSweep', 'sellIntoBidByOwnerSig', 'crossBidSide') THEN 'out'
                    ELSE NULL
                END AS direction,
                CASE
                    WHEN a.action = 'continuation' THEN 'created'
                    WHEN a.action = 'spend' THEN 'spent'
                    ELSE 'confirmed'
                END AS status,
                CASE
                    WHEN a.inputs ? 'previousOutpoint' THEN jsonb_build_array(a.inputs->'previousOutpoint')
                    ELSE '[]'::jsonb
                END AS input_outpoints,
                CASE
                    WHEN a.outputs ? 'vout' THEN jsonb_build_array(jsonb_build_object(
                        'txidHex', encode(a.txid, 'hex'),
                        'vout', a.outputs->'vout'
                    ))
                    ELSE '[]'::jsonb
                END AS output_outpoints,
                CASE
                    WHEN c.template_name = 'KCC20Wrapper'
                      OR c.claimed_template = 'KCC20Wrapper'
                      OR a.entrypoint IN ('wrap', 'unwrap')
                    THEN encode(a.covenant_id, 'hex')
                    ELSE NULL
                END AS wrapper_covenant_id,
                c.address
            FROM __FROM__
            LEFT JOIN LATERAL (
                SELECT a.outputs->'state' AS state
                WHERE a.outputs ? 'state'
            ) output_state ON TRUE
            WHERE COALESCE(c.template_name, c.claimed_template) IN (
                'KCC20', 'KCC20Orderbook',
                'KCC20Wrapper', 'KCC20FeeTicket'
            )
              AND __SCOPE__
"#;

fn kcc20_owner_action_source_sql(scope: &str, family_first: bool) -> String {
    let source = if family_first {
        r#"eligible_covenants c
            CROSS JOIN LATERAL (
                SELECT * FROM covenant_actions candidate
                WHERE candidate.covenant_id = c.covenant_id
                OFFSET 0
            ) a"#
    } else {
        "covenant_actions a JOIN covenants c ON c.covenant_id = a.covenant_id"
    };
    KCC20_OWNER_ACTION_SELECT_SQL
        .replace("__FROM__", source)
        .replace("__SCOPE__", scope)
}

const KCC20_OWNER_HISTORY_COLUMNS: &str = "owner, normalized_action, txid_hex, block_time_ms, token_id, canonical_token_id, wrapped_token_id, amount, direction, status, input_outpoints, output_outpoints, covenant_id_hex, wrapper_covenant_id, entrypoint, template_name, address, action_id";

const KCC20_FEE_OWNER_TRADE_SELECT: &str = r#"
    SELECT owner,'trade'::TEXT AS normalized_action,txid_hex,block_time_ms,
           canonical_token_id AS token_id,canonical_token_id,market_id AS wrapped_token_id,
           amount,direction,'spent'::TEXT AS status,input_outpoints,output_outpoints,
           market_id AS covenant_id_hex,market_id AS wrapper_covenant_id,entrypoint,
           CASE WHEN entrypoint='sellIntoBids' THEN 'KCC20OrderbookFeeHolderV1'
                ELSE 'KCC20OrderbookFeeAskV1' END AS template_name,
           address,source_action_id AS action_id,fill_index,party
    FROM kcc20_fee_owner_trades
"#;

pub async fn kcc20_actions_for_owner(
    pool: &PgPool,
    owner_or_address: &str,
    token_id_hex: Option<&str>,
    action_filter: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20OwnerActionRow>> {
    let owner_hex = if owner_or_address.len() == 64
        && owner_or_address.bytes().all(|b| b.is_ascii_hexdigit())
    {
        Some(owner_or_address.to_ascii_lowercase())
    } else {
        None
    };
    let address = if owner_hex.is_some() {
        None
    } else {
        Some(owner_or_address)
    };

    let mut tx = pool.begin().await?;
    set_local_query_limits(
        &mut tx,
        API_READ_LOCK_TIMEOUT,
        KCC20_OWNER_ACTION_STATEMENT_TIMEOUT,
    )
    .await?;
    sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
    // Keep the old read path bounded while the new history table is backfilled.
    let sql = format!(
        r#"WITH eligible_covenants AS MATERIALIZED (
            SELECT covenant_id, template_name, claimed_template, address
            FROM covenants
            WHERE COALESCE(template_name, claimed_template) IN (
                'KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket'
            )
              AND ($2::TEXT IS NULL OR address = $2)
        ), action_rows AS ({}), combined AS (
            SELECT {KCC20_OWNER_HISTORY_COLUMNS},0::BIGINT AS fill_index,''::TEXT AS party FROM action_rows
            UNION ALL {KCC20_FEE_OWNER_TRADE_SELECT}
        )
        SELECT *
        FROM combined
        WHERE ($1::TEXT IS NULL OR owner = $1)
          AND ($2::TEXT IS NULL OR address = $2)
          AND ($3::TEXT IS NULL OR token_id = $3 OR canonical_token_id = $3 OR wrapped_token_id = $3)
          AND ($4::TEXT IS NULL OR normalized_action = $4)
        ORDER BY block_time_ms DESC, txid_hex DESC, action_id DESC, fill_index DESC, party DESC
        LIMIT $5 OFFSET $6"#,
        kcc20_owner_action_source_sql("TRUE", true)
    );
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(owner_hex.as_deref())
        .bind(address)
        .bind(token_id_hex)
        .bind(action_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(rows.into_iter().map(kcc20_owner_action_from_row).collect())
}

fn kcc20_owner_action_from_row(r: PgRow) -> Kcc20OwnerActionRow {
    Kcc20OwnerActionRow {
        owner: r.get("owner"),
        action: r.get("normalized_action"),
        txid_hex: r.get("txid_hex"),
        block_time_ms: r.get("block_time_ms"),
        token_id: r.get("token_id"),
        canonical_token_id: r.get("canonical_token_id"),
        wrapped_token_id: r.get("wrapped_token_id"),
        amount: r.get("amount"),
        direction: r.get("direction"),
        status: r.get("status"),
        input_outpoints: r.get("input_outpoints"),
        output_outpoints: r.get("output_outpoints"),
        covenant_id_hex: r.get("covenant_id_hex"),
        wrapper_covenant_id: r.get("wrapper_covenant_id"),
        entrypoint: r.get("entrypoint"),
        template_name: r.get("template_name"),
    }
}

fn kcc20_owner_action_insert_sql(scope: &str) -> String {
    let source = kcc20_owner_action_source_sql(scope, false);
    format!(
        r#"WITH action_rows AS ({source})
        INSERT INTO kcc20_owner_action_history (
            action_id, txid, txid_hex, block_time_ms, owner, address, normalized_action,
            token_id, canonical_token_id, wrapped_token_id, amount, direction,
            status, input_outpoints, output_outpoints, covenant_id_hex,
            wrapper_covenant_id, entrypoint, template_name
        )
        SELECT action_id, txid_bytes, txid_hex, block_time_ms, owner, address, normalized_action,
               token_id, canonical_token_id, wrapped_token_id, amount, direction,
               status, input_outpoints, output_outpoints, covenant_id_hex,
               wrapper_covenant_id, entrypoint, template_name
        FROM action_rows
        WHERE TRUE
        ON CONFLICT (action_id) DO UPDATE SET
            txid = EXCLUDED.txid,
            txid_hex = EXCLUDED.txid_hex,
            block_time_ms = EXCLUDED.block_time_ms,
            owner = EXCLUDED.owner,
            address = EXCLUDED.address,
            normalized_action = EXCLUDED.normalized_action,
            token_id = EXCLUDED.token_id,
            canonical_token_id = EXCLUDED.canonical_token_id,
            wrapped_token_id = EXCLUDED.wrapped_token_id,
            amount = EXCLUDED.amount,
            direction = EXCLUDED.direction,
            status = EXCLUDED.status,
            input_outpoints = EXCLUDED.input_outpoints,
            output_outpoints = EXCLUDED.output_outpoints,
            covenant_id_hex = EXCLUDED.covenant_id_hex,
            wrapper_covenant_id = EXCLUDED.wrapper_covenant_id,
            entrypoint = EXCLUDED.entrypoint,
            template_name = EXCLUDED.template_name"#
    )
}

/// Capture a consistent starting boundary after the new projector has replaced
/// the old one. The dirty queue must retain every write after this boundary.
pub async fn initialize_kcc20_owner_action_backfill(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(AssertSqlSafe(format!(
        "SELECT pg_advisory_xact_lock({KCC20_PROJECTION_DIRTY_COMMIT_BARRIER_SQL})"
    )))
    .execute(&mut *tx)
    .await?;
    let dirty_start_id: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM kcc20_projection_dirty")
            .fetch_one(&mut *tx)
            .await?;
    let max_action_id: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM covenant_actions")
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query(
        r#"INSERT INTO kcc20_owner_action_backfill
           (singleton, dirty_start_id, max_action_id)
           VALUES (TRUE, $1, $2) ON CONFLICT (singleton) DO NOTHING"#,
    )
    .bind(dirty_start_id)
    .bind(max_action_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"INSERT INTO kcc20_projection_state (name, last_dirty_id, refreshed_at_ms)
           SELECT 'owner_action_history', dirty_start_id,
                  EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
           FROM kcc20_owner_action_backfill WHERE singleton
           ON CONFLICT (name) DO UPDATE SET
             last_dirty_id = GREATEST(kcc20_projection_state.last_dirty_id, EXCLUDED.last_dirty_id)"#,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn delete_stale_kcc20_owner_actions_tx(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<u64> {
    let deleted = sqlx::query(
        r#"WITH stale AS (
             SELECT h.action_id FROM kcc20_owner_action_history h
             WHERE NOT EXISTS (
                 SELECT 1 FROM covenant_actions a
                 JOIN covenants c ON c.covenant_id = a.covenant_id
                 WHERE a.id = h.action_id
                   AND COALESCE(c.template_name, c.claimed_template) IN
                       ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')
             )
             ORDER BY h.action_id LIMIT $1
           )
           DELETE FROM kcc20_owner_action_history h USING stale
           WHERE h.action_id = stale.action_id"#,
    )
    .bind(limit.clamp(1, 2_000))
    .execute(&mut **tx)
    .await?;
    Ok(deleted.rows_affected())
}

/// Returns true once the source scan has finished. Repeating a batch is safe.
pub async fn backfill_kcc20_owner_action_history_batch(
    pool: &PgPool,
    batch_size: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let state = sqlx::query(
        r#"SELECT target_covenant_id, covenant_cursor, action_cursor,
                  scan_template_name, scan_address, scan_template_initialized,
                  max_action_id, complete
           FROM kcc20_owner_action_backfill WHERE singleton FOR UPDATE"#,
    )
    .fetch_one(&mut *tx)
    .await?;
    if state.get::<bool, _>("complete") {
        tx.commit().await?;
        return Ok(true);
    }
    let cursor: Option<Vec<u8>> = state.get("covenant_cursor");
    let target: Option<Vec<u8>> = state.get("target_covenant_id");
    let action_cursor: i64 = state.get("action_cursor");
    let max_action_id: i64 = state.get("max_action_id");
    let covenant = if let Some(target) = target.as_ref() {
        target.clone()
    } else if let Some(cursor) = cursor {
        cursor
    } else {
        let first: Option<Vec<u8>> = sqlx::query_scalar(
            r#"SELECT covenant_id FROM covenants
               WHERE COALESCE(template_name, claimed_template) IN
                     ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')
               ORDER BY covenant_id LIMIT 1"#,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(first) = first else {
            if delete_stale_kcc20_owner_actions_tx(&mut tx, batch_size).await? > 0 {
                tx.commit().await?;
                return Ok(false);
            }
            sqlx::query("DELETE FROM kcc20_owner_action_covenant_state")
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE kcc20_owner_action_backfill SET complete = TRUE WHERE singleton")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(true);
        };
        first
    };
    let current = sqlx::query(
        "SELECT COALESCE(template_name, claimed_template) AS template_name, address FROM covenants WHERE covenant_id = $1 FOR SHARE",
    )
    .bind(&covenant)
    .fetch_optional(&mut *tx)
    .await?;
    let current_template: Option<String> =
        current.as_ref().and_then(|row| row.get("template_name"));
    let current_address: Option<String> = current.as_ref().map(|row| row.get("address"));
    if !state.get::<bool, _>("scan_template_initialized") {
        sqlx::query(
            r#"UPDATE kcc20_owner_action_backfill SET covenant_cursor = $1,
               scan_template_name = $2, scan_address = $3,
               scan_template_initialized = TRUE WHERE singleton"#,
        )
        .bind(&covenant)
        .bind(&current_template)
        .bind(&current_address)
        .execute(&mut *tx)
        .await?;
    } else if state.get::<Option<String>, _>("scan_template_name") != current_template
        || state.get::<Option<String>, _>("scan_address") != current_address
    {
        sqlx::query(
            r#"UPDATE kcc20_owner_action_backfill SET action_cursor = 0,
               scan_template_name = $1, scan_address = $2 WHERE singleton"#,
        )
        .bind(&current_template)
        .bind(&current_address)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(false);
    }
    let ids: Vec<i64> = sqlx::query_scalar(
        r#"SELECT id FROM covenant_actions
           WHERE covenant_id = $1 AND id > $2 AND id <= $3
           ORDER BY id LIMIT $4"#,
    )
    .bind(&covenant)
    .bind(action_cursor)
    .bind(max_action_id)
    .bind(batch_size.clamp(1, 2_000))
    .fetch_all(&mut *tx)
    .await?;
    if let Some(last_id) = ids.last() {
        sqlx::query("DELETE FROM kcc20_owner_action_history WHERE action_id = ANY($1::BIGINT[])")
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        sqlx::query(AssertSqlSafe(kcc20_owner_action_insert_sql(
            "a.id = ANY($1::BIGINT[])",
        )))
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE kcc20_owner_action_backfill SET covenant_cursor = $1, action_cursor = $2 WHERE singleton",
        )
        .bind(&covenant)
        .bind(last_id)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("DELETE FROM kcc20_owner_action_covenant_state WHERE covenant_id = $1")
            .bind(&covenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"INSERT INTO kcc20_owner_action_covenant_state (covenant_id, template_name, address)
               SELECT covenant_id, COALESCE(template_name, claimed_template), address
               FROM covenants WHERE covenant_id = $1
                 AND COALESCE(template_name, claimed_template) IN
                     ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')"#,
        )
        .bind(&covenant)
        .execute(&mut *tx)
        .await?;
        let next: Option<Vec<u8>> = if target.is_some() {
            None
        } else {
            sqlx::query_scalar(
                r#"SELECT covenant_id FROM covenants
                   WHERE covenant_id > $1
                     AND COALESCE(template_name, claimed_template) IN
                         ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket')
                   ORDER BY covenant_id LIMIT 1"#,
            )
            .bind(&covenant)
            .fetch_optional(&mut *tx)
            .await?
        };
        if let Some(next) = next {
            sqlx::query(
                "UPDATE kcc20_owner_action_backfill SET covenant_cursor = $1, action_cursor = 0, scan_template_name = NULL, scan_address = NULL, scan_template_initialized = FALSE WHERE singleton",
            )
            .bind(next)
            .execute(&mut *tx)
            .await?;
        } else {
            // A full rebuild also removes covenants that lost KCC20 identity.
            if target.is_none() {
                if delete_stale_kcc20_owner_actions_tx(&mut tx, batch_size).await? > 0 {
                    tx.commit().await?;
                    return Ok(false);
                }
            }
            sqlx::query("UPDATE kcc20_owner_action_backfill SET complete = TRUE, target_covenant_id = NULL WHERE singleton")
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(false)
}

async fn reset_kcc20_owner_action_backfill_tx(
    tx: &mut Transaction<'_, Postgres>,
    through_dirty_id: i64,
) -> Result<()> {
    let max_action_id: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM covenant_actions")
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query(
        r#"UPDATE kcc20_owner_action_backfill SET dirty_start_id = $1,
           max_action_id = $2, target_covenant_id = NULL,
           covenant_cursor = NULL, action_cursor = 0,
           scan_template_name = NULL, scan_address = NULL,
           scan_template_initialized = FALSE,
           complete = FALSE, ready = FALSE WHERE singleton"#,
    )
    .bind(through_dirty_id)
    .bind(max_action_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM kcc20_owner_action_covenant_state")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE kcc20_projection_state SET last_dirty_id = $1 WHERE name = 'owner_action_history'",
    )
    .bind(through_dirty_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn reset_kcc20_owner_action_covenant_tx(
    tx: &mut Transaction<'_, Postgres>,
    covenant_id: &[u8],
    last_dirty_id: i64,
) -> Result<()> {
    let max_action_id: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id), 0)::BIGINT FROM covenant_actions")
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query(
        r#"UPDATE kcc20_owner_action_backfill SET dirty_start_id = $1,
           max_action_id = $2, target_covenant_id = $3,
           covenant_cursor = $3, action_cursor = 0,
           scan_template_name = NULL, scan_address = NULL,
           scan_template_initialized = FALSE,
           complete = FALSE, ready = FALSE WHERE singleton"#,
    )
    .bind(last_dirty_id)
    .bind(max_action_id)
    .bind(covenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Apply a bounded dirty-transaction page and its watermark in one commit.
/// A null txid requests a fresh bounded backfill before reads can switch back.
pub async fn refresh_kcc20_owner_action_history(
    pool: &PgPool,
    pass_dirty_id: i64,
    batch_size: i64,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let state = sqlx::query(
        "SELECT complete, ready FROM kcc20_owner_action_backfill WHERE singleton FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(state) = state else {
        tx.commit().await?;
        return Ok(());
    };
    if !state.get::<bool, _>("complete") {
        tx.commit().await?;
        return Ok(());
    }
    let last_dirty_id: i64 = sqlx::query_scalar(
        "SELECT last_dirty_id FROM kcc20_projection_state WHERE name = 'owner_action_history' FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let dirty = sqlx::query(
        r#"SELECT id, txid FROM kcc20_projection_dirty
           WHERE id > $1 AND id <= $2 ORDER BY id LIMIT $3"#,
    )
    .bind(last_dirty_id)
    .bind(pass_dirty_id)
    .bind(batch_size.clamp(1, 2_000))
    .fetch_all(&mut *tx)
    .await?;
    if let Some(null_row) = dirty
        .iter()
        .find(|row| row.get::<Option<Vec<u8>>, _>("txid").is_none())
    {
        let null_id: i64 = null_row.get("id");
        reset_kcc20_owner_action_backfill_tx(&mut tx, null_id).await?;
        tx.commit().await?;
        return Ok(());
    }
    let txids: Vec<Vec<u8>> = dirty
        .iter()
        .filter_map(|row| row.get::<Option<Vec<u8>>, _>("txid"))
        .collect();
    if !txids.is_empty() {
        let changed_covenant: Option<Vec<u8>> = sqlx::query_scalar(
            r#"WITH touched AS (
                 SELECT DISTINCT a.covenant_id FROM covenant_actions a
                 WHERE a.txid = ANY($1::BYTEA[])
               )
               SELECT touched.covenant_id FROM touched
                 JOIN covenants c ON c.covenant_id = touched.covenant_id
                 LEFT JOIN kcc20_owner_action_covenant_state known
                   ON known.covenant_id = touched.covenant_id
                 WHERE (known.covenant_id IS NULL
                   AND COALESCE(c.template_name, c.claimed_template) IN
                     ('KCC20', 'KCC20Orderbook', 'KCC20Wrapper', 'KCC20FeeTicket'))
                   OR (known.covenant_id IS NOT NULL
                     AND (known.template_name IS DISTINCT FROM COALESCE(c.template_name, c.claimed_template)
                       OR known.address IS DISTINCT FROM c.address))
               ORDER BY touched.covenant_id LIMIT 1"#,
        )
        .bind(&txids)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(covenant_id) = changed_covenant {
            reset_kcc20_owner_action_covenant_tx(&mut tx, &covenant_id, last_dirty_id).await?;
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("DELETE FROM kcc20_owner_action_history WHERE txid = ANY($1::BYTEA[])")
            .bind(&txids)
            .execute(&mut *tx)
            .await?;
        sqlx::query(AssertSqlSafe(kcc20_owner_action_insert_sql(
            "a.txid = ANY($1::BYTEA[])",
        )))
        .bind(&txids)
        .execute(&mut *tx)
        .await?;
    }
    // A fully pruned queue reports pass_dirty_id = 0. Keep the saved watermark
    // until a newer dirty row arrives, or the next pass would scan from zero.
    let through = dirty
        .last()
        .map_or(last_dirty_id.max(pass_dirty_id), |row| row.get("id"));
    sqlx::query(
        r#"UPDATE kcc20_projection_state SET last_dirty_id = GREATEST(last_dirty_id, $1),
           refreshed_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
           WHERE name = 'owner_action_history'"#,
    )
    .bind(through)
    .execute(&mut *tx)
    .await?;
    let caught_up: bool = sqlx::query_scalar(
        r#"SELECT NOT EXISTS (
             SELECT 1 FROM kcc20_projection_dirty WHERE id > $1 AND id <= $2
           )"#,
    )
    .bind(through)
    .bind(pass_dirty_id)
    .fetch_one(&mut *tx)
    .await?;
    if caught_up && !state.get::<bool, _>("ready") {
        sqlx::query("UPDATE kcc20_owner_action_backfill SET ready = TRUE WHERE singleton")
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn kcc20_owner_action_history_ready(pool: &PgPool) -> Result<bool> {
    let ready = sqlx::query_scalar(
        "SELECT COALESCE((SELECT ready FROM kcc20_owner_action_backfill WHERE singleton), FALSE)",
    )
    .fetch_one(pool)
    .await?;
    Ok(ready)
}

fn kcc20_owner_action_materialized_query(owner_or_address: &str) -> (String, String) {
    let owner_hex =
        owner_or_address.len() == 64 && owner_or_address.bytes().all(|b| b.is_ascii_hexdigit());
    let (scope, lookup) = if owner_hex {
        ("owner = $1", owner_or_address.to_ascii_lowercase())
    } else {
        ("address = $1", owner_or_address.to_string())
    };
    let sql = format!(
        r#"
        WITH combined AS (
            SELECT {KCC20_OWNER_HISTORY_COLUMNS},0::BIGINT AS fill_index,''::TEXT AS party
            FROM kcc20_owner_action_history
            UNION ALL {KCC20_FEE_OWNER_TRADE_SELECT}
        )
        SELECT owner, normalized_action, txid_hex,
               block_time_ms, token_id, canonical_token_id, wrapped_token_id,
               amount, direction, status, input_outpoints, output_outpoints,
               covenant_id_hex, wrapper_covenant_id, entrypoint, template_name
        FROM combined
        WHERE {scope}
          AND ($2::TEXT IS NULL OR token_id = $2 OR canonical_token_id = $2 OR wrapped_token_id = $2)
          AND ($3::TEXT IS NULL OR normalized_action = $3)
        ORDER BY block_time_ms DESC, txid_hex DESC, action_id DESC, fill_index DESC, party DESC
        LIMIT $4 OFFSET $5
        "#,
    );
    (sql, lookup)
}

pub async fn kcc20_actions_for_owner_materialized(
    pool: &PgPool,
    owner_or_address: &str,
    token_id_hex: Option<&str>,
    action_filter: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20OwnerActionRow>> {
    let (sql, lookup) = kcc20_owner_action_materialized_query(owner_or_address);
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(lookup)
        .bind(token_id_hex)
        .bind(action_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(kcc20_owner_action_from_row).collect())
}

/// Read readiness and history from one snapshot so a concurrent rebuild cannot
/// expose a partially replaced action page.
pub async fn kcc20_actions_for_owner_materialized_if_ready(
    pool: &PgPool,
    owner_or_address: &str,
    token_id_hex: Option<&str>,
    action_filter: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Option<Vec<Kcc20OwnerActionRow>>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let ready: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT ready FROM kcc20_owner_action_backfill WHERE singleton), FALSE)",
    )
    .fetch_one(&mut *tx)
    .await?;
    if !ready {
        tx.commit().await?;
        return Ok(None);
    }
    let (sql, lookup) = kcc20_owner_action_materialized_query(owner_or_address);
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(lookup)
        .bind(token_id_hex)
        .bind(action_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(
        rows.into_iter().map(kcc20_owner_action_from_row).collect(),
    ))
}

pub async fn kcc20_balances_for_owner(
    pool: &PgPool,
    owner_hex: &str,
) -> Result<Vec<Kcc20BalanceRow>> {
    kcc20_balances_for_owner_paged(pool, owner_hex, 10_000, 0).await
}

pub async fn kcc20_balances_for_owner_paged(
    pool: &PgPool,
    owner_hex: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Kcc20BalanceRow>> {
    let owner = hex::decode(owner_hex)?;
    let rows = sqlx::query(
        r#"
        SELECT
            encode(covenant_id, 'hex') AS token_id_hex,
            encode(owner_identifier, 'hex') AS owner_identifier,
            identifier_type,
            amount_total::TEXT AS amount,
            utxo_count,
            is_minter,
            last_change_ms
        FROM kcc20_holders
        WHERE owner_identifier = $1
          AND is_minter = FALSE
        ORDER BY amount_total DESC, token_id_hex ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(owner)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let identifier_type = r.get::<i16, _>("identifier_type");
            Kcc20BalanceRow {
                token_id_hex: r.get("token_id_hex"),
                owner_identifier: r.get("owner_identifier"),
                identifier_type,
                identifier_type_name: kcc20_identifier_type_name(identifier_type).to_string(),
                amount: r.get("amount"),
                utxo_count: r.get("utxo_count"),
                is_minter: r.get("is_minter"),
                last_change_ms: r.get("last_change_ms"),
            }
        })
        .collect())
}

pub async fn kcc20_balances_for_owner_count(pool: &PgPool, owner_hex: &str) -> Result<i64> {
    let owner = hex::decode(owner_hex)?;
    let count = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM kcc20_holders WHERE owner_identifier = $1 AND is_minter = FALSE",
    )
    .bind(owner)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn kcc20_portfolio_for_owner(
    pool: &PgPool,
    owner_hex: &str,
    options: Kcc20PortfolioOptions,
) -> Result<(Vec<Kcc20PortfolioRow>, i64)> {
    let owner = hex::decode(owner_hex)?;
    let limit = options.limit.clamp(1, 1_000);
    let offset = options.offset.max(0);
    let rows = sqlx::query(
        r#"
        WITH owner_native AS (
            SELECT
                h.covenant_id AS canonical_token_id,
                SUM(h.amount_total) AS native_balance,
                SUM(h.utxo_count)::BIGINT AS native_utxo_count,
                MAX(h.last_change_ms) AS native_last_change_ms
            FROM kcc20_holders h
            LEFT JOIN kcc20_portfolio_market_identities self_wrapper
              ON self_wrapper.wrapper_id = h.covenant_id
            WHERE h.owner_identifier = $1
              AND h.is_minter = FALSE
              AND self_wrapper.wrapper_id IS NULL
              AND ($7::BOOLEAN OR h.amount_total > 0)
            GROUP BY h.covenant_id
        ),
        owner_wrapped_markets AS (
            SELECT
                w.canonical_token_id,
                w.wrapper_id,
                SUM(h.amount_total) AS orderbook_balance,
                SUM(h.utxo_count)::BIGINT AS orderbook_utxo_count,
                MAX(h.last_change_ms) AS orderbook_last_change_ms
            FROM kcc20_holders h
            JOIN kcc20_portfolio_market_identities w
              ON w.wrapper_id = h.covenant_id
            WHERE $2::BOOLEAN
              AND h.owner_identifier = $1
              AND h.is_minter = FALSE
              AND ($7::BOOLEAN OR h.amount_total > 0)
            GROUP BY w.canonical_token_id, w.wrapper_id
        ),
        owner_wrapped AS (
            SELECT
                canonical_token_id,
                SUM(orderbook_balance) AS orderbook_balance,
                SUM(orderbook_utxo_count)::BIGINT AS orderbook_utxo_count,
                MAX(orderbook_last_change_ms) AS orderbook_last_change_ms
            FROM owner_wrapped_markets
            GROUP BY canonical_token_id
        ),
        canonical_ids AS (
            SELECT canonical_token_id FROM owner_native
            UNION
            SELECT canonical_token_id FROM owner_wrapped WHERE $2::BOOLEAN
        ),
        grouped AS (
            SELECT
                ids.canonical_token_id,
                COALESCE(native.native_balance, 0) AS native_balance,
                COALESCE(native.native_utxo_count, 0) AS native_utxo_count,
                native.native_last_change_ms,
                CASE WHEN $2::BOOLEAN THEN COALESCE(w.orderbook_balance, 0) ELSE 0 END AS orderbook_balance,
                CASE WHEN $2::BOOLEAN THEN COALESCE(w.orderbook_utxo_count, 0) ELSE 0 END AS orderbook_utxo_count,
                CASE WHEN $2::BOOLEAN THEN w.orderbook_last_change_ms ELSE NULL END AS orderbook_last_change_ms
            FROM canonical_ids ids
            LEFT JOIN owner_native native
              ON native.canonical_token_id = ids.canonical_token_id
            LEFT JOIN owner_wrapped w
              ON w.canonical_token_id = ids.canonical_token_id
            WHERE $7::BOOLEAN
               OR COALESCE(native.native_balance, 0) > 0
               OR ($2::BOOLEAN AND COALESCE(w.orderbook_balance, 0) > 0)
        ),
        counted AS (
            SELECT
                grouped.*,
                COUNT(*) OVER() AS total_count
            FROM grouped
        ),
        paged AS (
            SELECT *
            FROM counted
            ORDER BY (native_balance + CASE WHEN $2::BOOLEAN THEN orderbook_balance ELSE 0 END) DESC,
                     canonical_token_id ASC
            LIMIT $5 OFFSET $6
        )
        SELECT
            encode(p.canonical_token_id, 'hex') AS canonical_token_id_hex,
            p.native_balance::TEXT AS native_balance,
            CASE WHEN $2::BOOLEAN THEN p.orderbook_balance::TEXT ELSE NULL END AS orderbook_balance,
            CASE WHEN $4::BOOLEAN THEN (p.native_balance + p.orderbook_balance)::TEXT ELSE NULL END AS total_balance,
            (p.native_utxo_count + CASE WHEN $2::BOOLEAN THEN p.orderbook_utxo_count ELSE 0 END)::BIGINT AS utxo_count,
            GREATEST(
                COALESCE(p.native_last_change_ms, 0),
                COALESCE(p.orderbook_last_change_ms, 0)
            )::BIGINT AS last_change_ms,
            CASE WHEN $2::BOOLEAN THEN COALESCE(wrapped.rows, '[]'::jsonb) ELSE NULL END AS wrapped_markets,
            CASE WHEN $3::BOOLEAN THEN COALESCE(reserves.rows, '[]'::jsonb) ELSE NULL END AS reserve_rows,
            p.total_count::BIGINT AS total_count
        FROM paged p
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'wrappedTokenIdHex', encode(m.wrapper_id, 'hex'),
                    'wrapperCovenantIdHex', encode(m.wrapper_id, 'hex'),
                    'orderbookBalance', m.orderbook_balance::TEXT,
                    'utxoCount', m.orderbook_utxo_count,
                    'lastChangeMs', m.orderbook_last_change_ms
                )
                ORDER BY m.orderbook_balance DESC, m.wrapper_id ASC
            ) AS rows
            FROM owner_wrapped_markets m
            WHERE m.canonical_token_id = p.canonical_token_id
        ) wrapped ON $2::BOOLEAN
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'ownerIdentifier', encode(h.owner_identifier, 'hex'),
                    'identifierType', h.identifier_type,
                    'identifierTypeName', $8::TEXT,
                    'amount', h.amount_total::TEXT,
                    'utxoCount', h.utxo_count,
                    'lastChangeMs', h.last_change_ms,
                    'wrapperCovenantIdHex', encode(ws.wrapper_id, 'hex')
                )
                ORDER BY h.amount_total DESC, ws.wrapper_id ASC
            ) AS rows
            FROM kcc20_portfolio_market_identities ws
            JOIN kcc20_holders h
              ON h.covenant_id = ws.canonical_token_id
             AND (
                 h.owner_identifier = ws.wrapper_id
                 OR h.owner_identifier IN (
                     SELECT decode(u.state->>'wrapperCovenantId', 'hex')
                     FROM covenant_utxos u
                     WHERE u.covenant_id = ws.wrapper_id
                       AND u.status = 'active'
                       AND u.state->>'wrapperCovenantId' ~ '^[0-9a-fA-F]{64}$'
                 )
             )
             AND h.identifier_type = 4
            WHERE ws.canonical_token_id = p.canonical_token_id
              AND ($7::BOOLEAN OR h.amount_total > 0)
        ) reserves ON $3::BOOLEAN
        "#,
    )
    .bind(&owner)
    .bind(options.include_wrapped)
    .bind(options.include_reserves)
    .bind(options.include_totals)
    .bind(limit)
    .bind(offset)
    .bind(options.include_empty)
    .bind(kcc20_identifier_type_name(4))
    .fetch_all(pool)
    .await?;

    let mut total = rows
        .first()
        .map(|row| row.get::<i64, _>("total_count"))
        .unwrap_or(0);
    if rows.is_empty() && offset > 0 {
        total = kcc20_portfolio_total_for_owner(pool, &owner, options).await?;
    }
    Ok((
        rows.into_iter()
            .map(|r| Kcc20PortfolioRow {
                canonical_token_id_hex: r.get("canonical_token_id_hex"),
                native_balance: r.get("native_balance"),
                utxo_count: r.get("utxo_count"),
                last_change_ms: r.get("last_change_ms"),
                orderbook_balance: r.get("orderbook_balance"),
                total_balance: r.get("total_balance"),
                wrapped_markets: r.get("wrapped_markets"),
                reserve_rows: r.get("reserve_rows"),
            })
            .collect(),
        total,
    ))
}

async fn kcc20_portfolio_total_for_owner(
    pool: &PgPool,
    owner: &[u8],
    options: Kcc20PortfolioOptions,
) -> Result<i64> {
    let row = sqlx::query(
        r#"
        WITH owner_native AS (
            SELECT
                h.covenant_id AS canonical_token_id,
                SUM(h.amount_total) AS native_balance
            FROM kcc20_holders h
            LEFT JOIN kcc20_portfolio_market_identities self_wrapper
              ON self_wrapper.wrapper_id = h.covenant_id
            WHERE h.owner_identifier = $1
              AND h.is_minter = FALSE
              AND self_wrapper.wrapper_id IS NULL
              AND ($3::BOOLEAN OR h.amount_total > 0)
            GROUP BY h.covenant_id
        ),
        owner_wrapped AS (
            SELECT
                w.canonical_token_id,
                SUM(h.amount_total) AS orderbook_balance
            FROM kcc20_holders h
            JOIN kcc20_portfolio_market_identities w
              ON w.wrapper_id = h.covenant_id
            WHERE $2::BOOLEAN
              AND h.owner_identifier = $1
              AND h.is_minter = FALSE
              AND ($3::BOOLEAN OR h.amount_total > 0)
            GROUP BY w.canonical_token_id
        ),
        canonical_ids AS (
            SELECT canonical_token_id FROM owner_native
            UNION
            SELECT canonical_token_id FROM owner_wrapped WHERE $2::BOOLEAN
        ),
        grouped AS (
            SELECT
                ids.canonical_token_id,
                COALESCE(native.native_balance, 0) AS native_balance,
                CASE WHEN $2::BOOLEAN THEN COALESCE(w.orderbook_balance, 0) ELSE 0 END AS orderbook_balance
            FROM canonical_ids ids
            LEFT JOIN owner_native native
              ON native.canonical_token_id = ids.canonical_token_id
            LEFT JOIN owner_wrapped w
              ON w.canonical_token_id = ids.canonical_token_id
            WHERE $3::BOOLEAN
               OR COALESCE(native.native_balance, 0) > 0
               OR ($2::BOOLEAN AND COALESCE(w.orderbook_balance, 0) > 0)
        )
        SELECT COUNT(*)::BIGINT AS total_count
        FROM grouped
        "#,
    )
    .bind(owner)
    .bind(options.include_wrapped)
    .bind(options.include_empty)
    .fetch_one(pool)
    .await?;
    Ok(row.get("total_count"))
}

pub async fn kcc20_portfolio_assets_for_owner(
    pool: &PgPool,
    owner_hex: &str,
    options: Kcc20PortfolioAssetOptions,
) -> Result<Kcc20PortfolioAssetPage> {
    let owner = hex::decode(owner_hex)?;
    let token_id = options
        .token_id_hex
        .as_deref()
        .map(hex::decode)
        .transpose()?;
    let search = options
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        });
    let sort_column = match options.sort_by.as_str() {
        "canonicalTokenIdHex" => "a.canonical_token_id",
        "nativeBalance" => "a.native_balance",
        "orderbookBalance" => "a.orderbook_balance",
        "totalBalance" => "a.total_balance",
        "assetUtxoCount" => "a.asset_utxo_count",
        "openAskAmount" => "a.open_ask_amount",
        "openBidAmount" => "a.open_bid_amount",
        "openOrderCount" => "a.open_order_count",
        "lastChangeMs" => "a.last_change_ms",
        "bestAskUnitPriceSompi" => "market.best_ask_unit_price_sompi",
        "valueSompi" => "valuation.value_sompi",
        _ => "a.canonical_token_id",
    };
    let sort_direction = if options.sort_direction.eq_ignore_ascii_case("desc") {
        "DESC"
    } else {
        "ASC"
    };
    let nullable_sort = matches!(
        options.sort_by.as_str(),
        "bestAskUnitPriceSompi" | "valueSompi"
    );
    let order_by = if sort_column == "a.canonical_token_id" {
        format!("{sort_column} {sort_direction}")
    } else if nullable_sort {
        format!("{sort_column} {sort_direction} NULLS LAST, a.canonical_token_id {sort_direction}")
    } else {
        format!("{sort_column} {sort_direction}, a.canonical_token_id {sort_direction}")
    };
    let limit = options.limit.clamp(1, 1_000);
    let offset = options.offset.max(0);

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, "3s").await?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM kcc20_owner_portfolio_assets a
        WHERE a.owner_identifier = $1
          AND ($2::BYTEA IS NULL OR a.canonical_token_id = $2)
          AND (
              $3::TEXT IS NULL
              OR encode(a.canonical_token_id, 'hex') LIKE '%' || lower($3) || '%' ESCAPE E'\\'
              OR lower(COALESCE(a.ticker, '')) LIKE '%' || lower($3) || '%' ESCAPE E'\\'
              OR lower(COALESCE(a.token_name, '')) LIKE '%' || lower($3) || '%' ESCAPE E'\\'
          )
          AND (NOT $4::BOOLEAN OR a.native_balance > 0)
          AND (NOT $5::BOOLEAN OR a.orderbook_balance > 0)
          AND (NOT $6::BOOLEAN OR a.open_order_count > 0)
        "#,
    )
    .bind(&owner)
    .bind(&token_id)
    .bind(&search)
    .bind(options.has_native_balance)
    .bind(options.has_orderbook_balance)
    .bind(options.has_open_orders)
    .fetch_one(&mut *tx)
    .await?;

    let sql = format!(
        include_str!("repo/kcc20_portfolio_assets.sql"),
        order_by = order_by,
    );
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(&owner)
        .bind(&token_id)
        .bind(&search)
        .bind(options.has_native_balance)
        .bind(options.has_orderbook_balance)
        .bind(options.has_open_orders)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Kcc20PortfolioAssetPage {
        items: rows
            .into_iter()
            .map(|r| {
                let wrapped_market_id_hex: Option<String> = r.get("wrapped_market_id_hex");
                let native_balance: String = r.get("native_balance");
                let orderbook_balance: String = r.get("orderbook_balance");
                let open_order_count: i64 = r.get("open_order_count");
                let actions = kcc20_portfolio_asset_actions(
                    wrapped_market_id_hex.is_some(),
                    native_balance != "0",
                    orderbook_balance != "0",
                    open_order_count > 0,
                );
                Kcc20PortfolioAssetRow {
                    canonical_token_id_hex: r.get("canonical_token_id_hex"),
                    wrapper_id_hex: r.get("wrapper_id_hex"),
                    wrapped_market_id_hex,
                    native_balance,
                    orderbook_balance,
                    total_balance: r.get("total_balance"),
                    asset_utxo_count: r.get("asset_utxo_count"),
                    open_ask_amount: r.get("open_ask_amount"),
                    open_bid_amount: r.get("open_bid_amount"),
                    open_order_count,
                    best_ask_unit_price_sompi: r.get("best_ask_unit_price_sompi"),
                    best_bid_unit_price_sompi: r.get("best_bid_unit_price_sompi"),
                    value_sompi: r.get("value_sompi"),
                    fee_ticket_supported: r.get("fee_ticket_supported"),
                    last_change_ms: r.get("last_change_ms"),
                    ticker: r.get("ticker"),
                    token_name: r.get("token_name"),
                    decimals: r.get("decimals"),
                    actions,
                }
            })
            .collect(),
        total,
    })
}

fn kcc20_portfolio_asset_actions(
    has_wrapper: bool,
    has_native_balance: bool,
    has_orderbook_balance: bool,
    has_open_orders: bool,
) -> Kcc20PortfolioAssetActions {
    Kcc20PortfolioAssetActions {
        wrap: Kcc20PortfolioAssetActionAvailability {
            enabled: has_wrapper && has_native_balance,
            reason: if !has_wrapper {
                Some("wrapper is not available".to_string())
            } else if has_native_balance {
                None
            } else {
                Some("no native KCC20 balance available to wrap".to_string())
            },
        },
        unwrap: Kcc20PortfolioAssetActionAvailability {
            enabled: has_wrapper && has_orderbook_balance,
            reason: if !has_wrapper {
                Some("wrapper is not available".to_string())
            } else if has_orderbook_balance {
                None
            } else {
                Some("no wrapped KCC20 balance available to unwrap".to_string())
            },
        },
        trade: Kcc20PortfolioAssetActionAvailability {
            enabled: has_wrapper && (has_orderbook_balance || has_open_orders),
            reason: if !has_wrapper {
                Some("wrapper is not available".to_string())
            } else if has_orderbook_balance || has_open_orders {
                None
            } else {
                Some("no wrapped KCC20 balance or open orders available".to_string())
            },
        },
    }
}

fn kcc20_identifier_type_name(identifier_type: i16) -> &'static str {
    match identifier_type {
        0 => "p2pk-schnorr/v1",
        1 => "p2pkh-schnorr/v1",
        2 => "p2pkh-ecdsa/v1",
        3 => "p2sh/v1",
        4 => "covenant-id/v1",
        _ => "unknown",
    }
}

fn rest_db_lag_blocks(live_score: Option<i64>, rest_score: Option<i64>) -> Option<i64> {
    Some(live_score?.saturating_sub(rest_score?).max(0))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KcomCampaignRead {
    pub graph_id: String,
    pub artifact_profile: String,
    pub test_only: bool,
    pub campaign_id: String,
    pub token_id: String,
    pub lifecycle: String,
    pub budget_raw: String,
    pub settled_raw: String,
    pub liability_raw: String,
    pub activated_raw: String,
    pub recovered_raw: String,
    pub reserve_raw: String,
    pub vault_txid: String,
    pub vault_vout: i32,
    pub selected_count: i64,
    pub closed_shards: i64,
    pub collected_shards: i64,
    pub settled_count: i64,
    pub shard_count: i64,
}

fn kcom_state_text<'a>(state: &'a Value, key: &str) -> Result<&'a str> {
    state.get(key).and_then(Value::as_str)
        .with_context(|| format!("authenticated KCOM state lacks {key}"))
}

fn kcom_state_raw(state: &Value, key: &str) -> Result<u64> {
    kcom_state_text(state, key)?.parse::<u64>()
        .with_context(|| format!("invalid KCOM raw amount {key}"))
}

pub async fn kcom_campaign(pool: &PgPool, graph_id: &str) -> Result<Option<KcomCampaignRead>> {
    anyhow::ensure!(graph_id.len() == 64 && graph_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "KCOM graph ID must be 32-byte hex");
    let graph_id = graph_id.to_ascii_lowercase();
    let graph = hex::decode(&graph_id)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx).await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, COVENANT_LIST_STATEMENT_TIMEOUT).await?;
    crate::deferred_decode::ensure_family_complete(&mut tx,&graph).await?;
    let vaults = sqlx::query(
        "SELECT encode(txid,'hex') AS txid, vout, state FROM covenant_utxos \
         WHERE covenant_id=$1 AND status='active' AND state->>'modeName'='KCOMVault' LIMIT 2",
    ).bind(&graph).fetch_all(&mut *tx).await?;
    if vaults.is_empty() {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM covenants WHERE covenant_id=$1)")
            .bind(&graph).fetch_one(&mut *tx).await?;
        anyhow::ensure!(!exists, "KCOM graph exists without an authenticated active vault");
        tx.commit().await?;
        return Ok(None);
    }
    anyhow::ensure!(vaults.len() == 1, "KCOM graph has multiple active vaults");
    let vault = &vaults[0];
    let state: Value = vault.get("state");
    let campaign_id = kcom_state_text(&state, "campaignId")?.to_owned();
    let token_id = kcom_state_text(&state, "canonicalTokenId")?.to_owned();
    let budget = kcom_state_raw(&state, "budget_raw")?;
    let liability = kcom_state_raw(&state, "liability_raw")?;
    let activated = kcom_state_raw(&state, "activated_raw")?;
    anyhow::ensure!(activated <= liability && liability <= budget,
        "KCOM beneficiary liabilities exceed budget");
    let outstanding = liability - activated;
    let recovered = state["recovered"].as_bool().context("KCOM vault recovered flag")?;
    let shard_state: Option<Value> = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 \
         AND state->>'modeName'='KCOMClaimShard' LIMIT 1",
    ).bind(&graph).fetch_optional(&mut *tx).await?;
    let shard_count = shard_state.as_ref().map(|s| kcom_state_raw(s, "shard_count"))
        .transpose()?.unwrap_or(0) as i64;
    let (selected, closed, collected, settled): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE entrypoint='select' AND decoded_args->>'modeName'='KCOMClaimShard'), \
                count(*) FILTER (WHERE entrypoint='close' AND decoded_args->>'modeName'='KCOMClaimShard'), \
                count(*) FILTER (WHERE entrypoint='collect' AND decoded_args->>'modeName'='KCOMSettlement'), \
                count(*) FILTER (WHERE entrypoint='settle' AND decoded_args->>'modeName'='KCOMSettlement') \
         FROM covenant_actions WHERE covenant_id=$1 AND action='spend'",
    ).bind(&graph).fetch_one(&mut *tx).await?;
    let token = hex::decode(&token_id)?;
    let reserve_text: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM((state->>'amount')::NUMERIC),0)::TEXT \
         FROM covenant_utxos WHERE covenant_id=$1 AND status='active' AND state->>'owner'=$2",
    ).bind(&token).bind(&graph_id).fetch_one(&mut *tx).await?;
    let reserve = reserve_text.parse::<u64>().context("invalid KCOM canonical reserve")?;
    anyhow::ensure!(reserve >= outstanding, "KCOM reserve does not cover beneficiary liabilities");
    let funded = state["funded"].as_bool().context("KCOM vault funded flag")?;
    let opened = state["opened"].as_bool().context("KCOM vault opened flag")?;
    let settled_flag = state["settled"].as_bool().context("KCOM vault settled flag")?;
    let lifecycle = if settled_flag {
        anyhow::ensure!(shard_count > 0 && closed == shard_count && collected == shard_count
            && selected == settled, "KCOM settlement history is incomplete");
        "settled"
    } else if !opened {
        if funded { "funded" } else { "draft" }
    } else if shard_count > 0 && closed == shard_count {
        if collected > 0 { "settling" } else { "closed" }
    } else {
        "open"
    };
    let result = KcomCampaignRead {
        graph_id: graph_id.to_owned(), campaign_id, token_id,
        artifact_profile: state.get("artifactProfile").and_then(Value::as_str)
            .unwrap_or("kcom-production-30d-v1").to_owned(),
        test_only: state.get("testOnly").and_then(Value::as_bool).unwrap_or(false),
        lifecycle: lifecycle.into(), budget_raw: budget.to_string(),
        settled_raw: liability.to_string(),
        liability_raw: outstanding.to_string(), activated_raw: activated.to_string(),
        recovered_raw: if recovered { (budget - liability).to_string() } else { "0".into() },
        reserve_raw: reserve.to_string(), vault_txid: vault.get("txid"), vault_vout: vault.get("vout"),
        selected_count: selected, closed_shards: closed, collected_shards: collected,
        settled_count: settled, shard_count,
    };
    tx.commit().await?;
    Ok(Some(result))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KcomParticipantRead {
    pub graph_id: String,
    pub original_authority: String,
    pub beneficiary: String,
    pub beneficiary_scheme: u64,
    pub tier: String,
    pub lifecycle: String,
    pub selection_txid: String,
    pub commitment_outpoint: String,
    pub entitlement_outpoint: Option<String>,
    pub allocation_raw: Option<String>,
    pub activation_txid: Option<String>,
    pub position_id: Option<String>,
    pub position_outpoint: Option<String>,
    pub released_raw: Option<String>,
    pub remaining_raw: Option<String>,
}

pub async fn kcom_participant(
    pool: &PgPool, graph_id: &str, authority: &str,
) -> Result<Option<KcomParticipantRead>> {
    anyhow::ensure!(graph_id.len() == 64 && graph_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "KCOM graph ID must be 32-byte hex");
    anyhow::ensure!(authority.len() == 64 && authority.bytes().all(|b| b.is_ascii_hexdigit()),
        "KCOM original authority must be 32-byte hex");
    let graph_id = graph_id.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let graph = hex::decode(&graph_id)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx).await?;
    set_local_query_limits(&mut tx, API_READ_LOCK_TIMEOUT, COVENANT_LIST_STATEMENT_TIMEOUT).await?;
    crate::deferred_decode::ensure_family_complete(&mut tx,&graph).await?;
    let rows = sqlx::query(
        "SELECT encode(txid,'hex') AS txid, vout, status, \
                encode(spent_by_txid,'hex') AS spent_by, state \
         FROM covenant_utxos WHERE covenant_id=$1 \
           AND state->>'original_authority'=$2 \
           AND state->>'modeName' IN ('KCOMClaimCommitment','KCOMEntitlement') \
         LIMIT 4",
    ).bind(&graph).bind(&authority).fetch_all(&mut *tx).await?;
    if rows.is_empty() {
        tx.commit().await?;
        return Ok(None);
    }
    let commitments = rows.iter().filter(|row| {
        row.get::<Value, _>("state")["modeName"] == "KCOMClaimCommitment"
    }).collect::<Vec<_>>();
    let entitlements = rows.iter().filter(|row| {
        row.get::<Value, _>("state")["modeName"] == "KCOMEntitlement"
    }).collect::<Vec<_>>();
    anyhow::ensure!(commitments.len() == 1 && entitlements.len() <= 1 && rows.len() <= 2,
        "KCOM participant history is ambiguous");
    let commitment = commitments[0];
    let selected: Value = commitment.get("state");
    let beneficiary = kcom_state_text(&selected, "beneficiary")?.to_owned();
    let scheme = selected["beneficiary_scheme"].as_u64()
        .context("KCOM beneficiary scheme missing")?;
    let tier = kcom_state_text(&selected, "tier")?.to_owned();
    let selection_txid: String = commitment.get("txid");
    let commitment_outpoint = format!("{}:{}", selection_txid, commitment.get::<i32, _>("vout"));
    let mut result = KcomParticipantRead {
        graph_id: graph_id.to_owned(), original_authority: authority.to_owned(),
        beneficiary: beneficiary.clone(), beneficiary_scheme: scheme, tier: tier.clone(),
        lifecycle: "selected".into(), selection_txid, commitment_outpoint,
        entitlement_outpoint: None, allocation_raw: None, activation_txid: None,
        position_id: None, position_outpoint: None, released_raw: None, remaining_raw: None,
    };
    if let Some(entitlement) = entitlements.first() {
        let state: Value = entitlement.get("state");
        let settlement_txid: String = entitlement.get("txid");
        let commitment_spent: Option<String> = commitment.get("spent_by");
        anyhow::ensure!(commitment.get::<String, _>("status") == "spent"
            && commitment_spent.as_deref() == Some(settlement_txid.as_str()),
            "KCOM entitlement lacks consumed commitment");
        anyhow::ensure!(kcom_state_text(&state, "beneficiary")? == beneficiary
            && kcom_state_text(&state, "tier")? == tier
            && kcom_state_text(&state, "original_authority")? == authority,
            "KCOM entitlement changes accepted selection");
        let total = kcom_state_raw(&state, "total")?;
        result.entitlement_outpoint = Some(format!("{}:{}", settlement_txid,
            entitlement.get::<i32, _>("vout")));
        result.allocation_raw = Some(total.to_string());
        result.released_raw = Some("0".into());
        result.remaining_raw = Some(total.to_string());
        result.lifecycle = "awaiting_activation".into();
        if entitlement.get::<String, _>("status") == "spent" {
            let activation_txid: String = entitlement.get::<Option<String>, _>("spent_by")
                .context("spent KCOM entitlement lacks activation txid")?;
            let positions = sqlx::query(
                "SELECT encode(covenant_id,'hex') AS id, encode(txid,'hex') AS txid, vout, state \
                 FROM covenant_utxos WHERE txid=$1 AND state->>'modeName'='kcom-vesting' LIMIT 2",
            ).bind(hex::decode(&activation_txid)?).fetch_all(&mut *tx).await?;
            anyhow::ensure!(positions.len() == 1, "KCOM activation lacks one authenticated position");
            let position = &positions[0];
            let position_state: Value = position.get("state");
            anyhow::ensure!(kcom_state_text(&position_state, "beneficiary")? == beneficiary
                && kcom_state_text(&position_state, "tier")? == tier
                && kcom_state_raw(&position_state, "total")? == total
                && kcom_state_raw(&position_state, "released")? == 0,
                "KCOM activation position changes entitlement");
            let position_id: String = position.get("id");
            let active = sqlx::query(
                "SELECT encode(txid,'hex') AS txid, vout, state FROM covenant_utxos \
                 WHERE covenant_id=$1 AND status='active' \
                   AND state->>'modeName'='kcom-vesting' LIMIT 2",
            ).bind(hex::decode(&position_id)?).fetch_all(&mut *tx).await?;
            anyhow::ensure!(active.len() <= 1, "KCOM position has multiple active successors");
            result.activation_txid = Some(activation_txid);
            result.position_id = Some(position_id.clone());
            if let Some(live) = active.first() {
                let live_state: Value = live.get("state");
                let released = kcom_state_raw(&live_state, "released")?;
                anyhow::ensure!(released < total
                    && kcom_state_raw(&live_state, "total")? == total
                    && kcom_state_text(&live_state, "beneficiary")? == beneficiary,
                    "KCOM position successor changes beneficiary or allocation");
                result.lifecycle = "active".into();
                result.position_outpoint = Some(format!("{}:{}",
                    live.get::<String, _>("txid"), live.get::<i32, _>("vout")));
                result.released_raw = Some(released.to_string());
                result.remaining_raw = Some((total - released).to_string());
            } else {
                let finished: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM covenant_actions WHERE covenant_id=$1 \
                     AND action='spend' AND entrypoint='finish')",
                ).bind(hex::decode(&position_id)?).fetch_one(&mut *tx).await?;
                anyhow::ensure!(finished, "KCOM position disappeared without final release");
                result.lifecycle = "fully_released".into();
                result.released_raw = Some(total.to_string());
                result.remaining_raw = Some("0".into());
            }
        }
    } else {
        anyhow::ensure!(commitment.get::<String, _>("status") == "active",
            "KCOM selected commitment was consumed without an entitlement");
    }
    tx.commit().await?;
    Ok(Some(result))
}

#[cfg(test)]
mod rest_db_lag_tests {
    use super::rest_db_lag_blocks;

    #[test]
    fn reports_the_live_gap_even_when_the_rest_cursor_is_current() {
        assert_eq!(
            rest_db_lag_blocks(Some(568_510_024), Some(562_002_571)),
            Some(6_507_453)
        );
        assert_eq!(rest_db_lag_blocks(Some(100), Some(101)), Some(0));
        assert_eq!(rest_db_lag_blocks(None, Some(100)), None);
    }
}

#[cfg(test)]
#[path = "repo/activity_identity_tests.rs"]
mod activity_identity_tests;
