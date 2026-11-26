//! Postgres-backed storage for KaspaCom Covenant Tools.
//!
//! Schema lives in `migrations/`. Call `migrate(&pool).await?` for schema
//! migrations and guarded managed-index convergence. Direct `sqlx migrate run`
//! applies schema migrations but can leave redundant indexes in place. Tables:
//!   blocks, covenants, covenant_utxos, covenant_actions, kcc20_holders.

use anyhow::{Context, Result};
pub use sqlx::PgPool;
use sqlx::{postgres::PgPoolOptions, PgConnection};
use std::time::{Duration, Instant};

pub mod api_payments;
pub mod claim;
pub mod deferred_decode;
pub mod persist;
pub mod repo;
pub mod shadow;

pub use persist::{is_transient_persist_error, PersistStats, Persister, PgPersister, RevertStats, SettledRecheckFence};

pub async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await
        .context("connecting to PostgreSQL")
}

/// Opt-in retirement of non-unique action indexes covered by existing indexes.
/// Ordinary migrations preserve them until operators request this convergence.
pub async fn migrate_retiring_action_prefix_indexes(pool: &PgPool) -> Result<()> {
    migrate_inner(pool, true).await
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    migrate_inner(pool, false).await
}

async fn migrate_inner(pool: &PgPool, retire_action_prefixes: bool) -> Result<()> {
    const MIGRATION_REPAIR_LOCK: i64 = 0x544e31325f4d4947;
    const LOCK_RETRY_INTERVAL: Duration = Duration::from_secs(5);
    const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(45 * 60);

    let mut lock_connection = pool
        .acquire()
        .await
        .context("acquiring migration repair connection")?;
    // A cancelled future skips the explicit advisory unlock below. Never
    // return that session-level ownership lock to an idle pool connection.
    lock_connection.close_on_drop();
    let lock_timeout = std::env::var("TN12_MIGRATION_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_LOCK_TIMEOUT);
    let lock_started = Instant::now();
    loop {
        let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
            .bind(MIGRATION_REPAIR_LOCK)
            .fetch_one(&mut *lock_connection)
            .await
            .context("trying migration ownership lock")?;
        if acquired {
            break;
        }
        anyhow::ensure!(
            lock_started.elapsed() < lock_timeout,
            "timed out after {}s waiting for migration ownership; another migrator is still active",
            lock_timeout.as_secs()
        );
        tracing::info!(
            waited_seconds = lock_started.elapsed().as_secs(),
            "waiting for the active database migrator"
        );
        tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
    }
    tracing::info!(
        waited_seconds = lock_started.elapsed().as_secs(),
        "acquired database migration ownership"
    );

    let migration_result: Result<()> = async {
        repair_invalid_concurrent_indexes(&mut lock_connection).await?;
        repair_recorded_backfill_index(&mut lock_connection).await?;
        sqlx::migrate!("./migrations")
            .run(&mut *lock_connection)
            .await
            .context("running migrations")?;
        ensure_concurrent_indexes(&mut lock_connection).await?;
        retire_redundant_action_index(&mut lock_connection).await?;
        if retire_action_prefixes {
            retire_action_prefix_indexes(&mut lock_connection).await?;
        }
        Ok(())
    }
    .await;

    let unlock_result = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_REPAIR_LOCK)
        .fetch_one(&mut *lock_connection)
        .await
        .context("releasing migration repair lock");

    migration_result?;
    if !unlock_result? {
        anyhow::bail!("migration repair lock was not held at release");
    }
    Ok(())
}

struct ConcurrentIndex {
    name: &'static str,
    drop_sql: &'static str,
    create_sql: &'static str,
}

const ACTIVE_BACKFILL_INDEX: ConcurrentIndex = ConcurrentIndex {
    name: "covenant_utxos_active_outpoint_backfill_idx",
    drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_active_outpoint_backfill_idx",
    create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_outpoint_backfill_idx ON covenant_utxos (txid, vout) INCLUDE (covenant_id, created_block) WHERE status='active' AND covenant_id IS NOT NULL",
};

// Migration 701 requires this index before it can publish the new function.
// If 700 was already recorded, SQLx will not recreate a missing/invalid index.
async fn repair_recorded_backfill_index(connection: &mut PgConnection) -> Result<()> {
    let has_migrations: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(&mut *connection).await?;
    if !has_migrations { return Ok(()); }
    let recorded: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=20261114070000 AND success)")
        .fetch_one(&mut *connection).await?;
    if recorded && index_validity(connection, ACTIVE_BACKFILL_INDEX.name).await? != Some(true) {
        sqlx::query(ACTIVE_BACKFILL_INDEX.create_sql).execute(&mut *connection).await
            .context("restoring recorded active-output backfill index before function migration")?;
    }
    Ok(())
}

const REQUIRED_CONCURRENT_INDEXES: &[ConcurrentIndex] = &[
    ACTIVE_BACKFILL_INDEX,
    ConcurrentIndex {
        name: "covenant_utxos_kcc20_owner_order_state_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_kcc20_owner_order_state_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_owner_order_state_idx \
                     ON covenant_utxos ((state->>'ownerIdentifier'), (state->>'mode'), covenant_id) \
                     WHERE status = 'active' AND state ? 'ownerIdentifier' \
                       AND state->>'mode' IN ('2', '3')",
    },
    ConcurrentIndex {
        name: "covenant_utxos_kcc20_fee_order_state_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_kcc20_fee_order_state_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_fee_order_state_idx \
                     ON covenant_utxos ((state->>'owner'), (state->>'mode'), covenant_id) \
                     WHERE status = 'active' AND NOT (state ? 'ownerIdentifier') \
                       AND state->>'feePolicyVersion' = '1' AND state ? 'feePolicy' \
                       AND state ? 'owner' AND state->>'mode' IN ('2', '3')",
    },
    ConcurrentIndex {
        name: "covenant_utxos_kcc20_public_fee_order_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_kcc20_public_fee_order_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_public_fee_order_idx \
                     ON covenant_utxos ((state->>'owner'), (state->>'mode'), covenant_id) \
                     WHERE status='active' AND NOT (state ? 'ownerIdentifier') \
                       AND state->>'feePolicyVersion'='1' AND state ? 'owner' \
                       AND state->>'mode' IN ('2', '3')",
    },
    ConcurrentIndex {
        name: "covenant_actions_deploy_vout_uniq",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_deploy_vout_uniq",
        create_sql: "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_deploy_vout_uniq \
                     ON covenant_actions (covenant_id, txid, action, ((outputs->>'vout'))) \
                     WHERE action='deploy' AND outputs ? 'vout'",
    },
    ConcurrentIndex {
        name: "covenant_actions_fee_trades_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_fee_trades_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_fee_trades_idx ON covenant_actions (block_time_ms DESC, txid, covenant_id) WHERE action='spend' AND entrypoint IN ('buyAsks','sellIntoBids','crossWithBid') AND decoded_args->>'feePolicyVersion'='1' AND decoded_args ? 'feePolicy'",
    },
    ConcurrentIndex {
        name: "covenant_utxos_fee_market_identity_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_fee_market_identity_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_fee_market_identity_idx \
                     ON covenant_utxos (covenant_id) \
                     WHERE state->>'feePolicyVersion' = '1' AND state ? 'feePolicy'",
    },
    ConcurrentIndex {
        name: "covenant_actions_genesis_discovery_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_genesis_discovery_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_genesis_discovery_idx ON covenant_actions (block_hash, id) INCLUDE (covenant_id) WHERE action IN ('deploy','continuation')",
    },
    ConcurrentIndex {
        name: "covenant_utxos_genesis_scan_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_genesis_scan_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_genesis_scan_idx ON covenant_utxos (covenant_id, txid, vout) INCLUDE (created_block)",
    },
    ConcurrentIndex {
        name: "covenant_actions_tx_covenant_action_id_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_tx_covenant_action_id_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_tx_covenant_action_id_idx \
                     ON covenant_actions (txid, covenant_id, action, id)",
    },
    ConcurrentIndex {
        name: "covenant_actions_revert_block_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_revert_block_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_revert_block_idx \
                     ON covenant_actions (block_hash) INCLUDE (action, covenant_id)",
    },
    ConcurrentIndex {
        name: "covenant_utxos_spent_block_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_spent_block_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_spent_block_idx \
                     ON covenant_utxos (spent_block) INCLUDE (covenant_id) \
                     WHERE spent_block IS NOT NULL",
    },
    ConcurrentIndex {
        name: "covenant_utxos_created_block_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_created_block_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_created_block_idx \
                     ON covenant_utxos (created_block)",
    },
    ConcurrentIndex {
        name: "covenants_genesis_block_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenants_genesis_block_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_genesis_block_idx \
                     ON covenants (genesis_block)",
    },
    ConcurrentIndex {
        name: "covenants_genesis_txid_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenants_genesis_txid_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_genesis_txid_idx \
                     ON covenants (genesis_txid) WHERE genesis_txid IS NOT NULL",
    },
    ConcurrentIndex {
        name: "covenants_script_hash_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenants_script_hash_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenants_script_hash_idx \
                     ON covenants (script_hash)",
    },
    ConcurrentIndex {
        name: "covenant_actions_covenant_time_id_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_covenant_time_id_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_covenant_time_id_idx \
                     ON covenant_actions (covenant_id, block_time_ms DESC, id DESC)",
    },
    ConcurrentIndex {
        name: "covenant_actions_covenant_id_id_idx",
        drop_sql: "DROP INDEX CONCURRENTLY IF EXISTS covenant_actions_covenant_id_id_idx",
        create_sql: "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_actions_covenant_id_id_idx \
                     ON covenant_actions (covenant_id, id)",
    },
    ConcurrentIndex {
        name: "covenant_utxos_active_covenant_amount_outpoint_idx",
        drop_sql:
            "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_active_covenant_amount_outpoint_idx",
        create_sql:
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_covenant_amount_outpoint_idx \
             ON covenant_utxos (covenant_id, amount_sompi DESC, txid ASC, vout ASC) \
             WHERE status = 'active'",
    },
    ConcurrentIndex {
        name: "covenant_utxos_active_address_amount_outpoint_idx",
        drop_sql:
            "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_active_address_amount_outpoint_idx",
        create_sql:
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_active_address_amount_outpoint_idx \
             ON covenant_utxos (address, amount_sompi DESC, txid ASC, vout ASC) \
             INCLUDE (covenant_id) WHERE status = 'active'",
    },
    ConcurrentIndex {
        name: "covenant_utxos_kcc20_active_mint_policy_idx",
        drop_sql:
            "DROP INDEX CONCURRENTLY IF EXISTS covenant_utxos_kcc20_active_mint_policy_idx",
        create_sql:
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS covenant_utxos_kcc20_active_mint_policy_idx \
             ON covenant_utxos (covenant_id) \
             WHERE status = 'active' \
               AND state->>'isMintAuthority' = 'true' \
               AND state->>'mintPolicy' ~ '^[12]$'",
    },
];

async fn repair_invalid_concurrent_indexes(connection: &mut PgConnection) -> Result<()> {
    for index in REQUIRED_CONCURRENT_INDEXES {
        if index_validity(connection, index.name).await? == Some(false) {
            sqlx::query(index.drop_sql)
                .execute(&mut *connection)
                .await
                .with_context(|| format!("dropping invalid index {}", index.name))?;
        }
    }
    Ok(())
}

async fn ensure_concurrent_indexes(connection: &mut PgConnection) -> Result<()> {
    for index in REQUIRED_CONCURRENT_INDEXES {
        if index_validity(connection, index.name).await? != Some(true) {
            sqlx::query(index.create_sql)
                .execute(&mut *connection)
                .await
                .with_context(|| format!("creating valid index {}", index.name))?;
        }
    }
    Ok(())
}

/// Run on every migration attempt, after replacement repair and creation.
/// Keeping the guard outside a recorded SQL migration also protects retries
/// after a failed concurrent drop. Direct SQLx migration never retires the index.
async fn retire_redundant_action_index(connection: &mut PgConnection) -> Result<()> {
    let replacement_valid: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indexrelid = to_regclass('public.covenant_actions_tx_covenant_action_id_idx')
              AND i.indisvalid AND i.indisready AND i.indislive
              AND NOT i.indisunique AND NOT i.indisprimary
              AND pg_get_indexdef(i.indexrelid) =
                  'CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON public.covenant_actions USING btree (txid, covenant_id, action, id)'
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .context("validating replacement action lookup index")?;
    anyhow::ensure!(
        replacement_valid,
        "action lookup replacement is not ready and valid with the required exact definition; preserving continuation index"
    );

    let retirement_safe: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indexrelid = to_regclass('public.covenant_actions_continuation_tx_idx')
              AND (i.indisunique OR i.indisprimary OR pg_get_indexdef(i.indexrelid) <>
                  'CREATE INDEX covenant_actions_continuation_tx_idx ON public.covenant_actions USING btree (txid, covenant_id, id DESC) WHERE (action = ''continuation''::text)')
        )
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .context("validating redundant continuation index")?;
    anyhow::ensure!(
        retirement_safe,
        "continuation index has an unexpected definition; preserving it"
    );

    // A separate autocommit statement is required by CONCURRENTLY. Never put
    // this together with its guard in one multi-statement SQL migration.
    sqlx::query("DROP INDEX CONCURRENTLY IF EXISTS public.covenant_actions_continuation_tx_idx")
        .execute(&mut *connection)
        .await
        .context("retiring redundant continuation action index")?;
    Ok(())
}

/// These targets are non-unique left prefixes, never integrity constraints.
/// Validate every pair before dropping any target. The migration ownership
/// lock remains held across validation, concurrent drops and retry repair.
async fn retire_action_prefix_indexes(connection: &mut PgConnection) -> Result<()> {
    const PAIRS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "public.actions_txid_idx",
            "CREATE INDEX actions_txid_idx ON public.covenant_actions USING btree (txid)",
            "public.covenant_actions_tx_covenant_action_id_idx",
            "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON public.covenant_actions USING btree (txid, covenant_id, action, id)",
            "DROP INDEX CONCURRENTLY IF EXISTS public.actions_txid_idx",
        ),
        (
            "public.actions_covenant_time_idx",
            "CREATE INDEX actions_covenant_time_idx ON public.covenant_actions USING btree (covenant_id, block_time_ms DESC)",
            "public.covenant_actions_covenant_time_id_idx",
            "CREATE INDEX covenant_actions_covenant_time_id_idx ON public.covenant_actions USING btree (covenant_id, block_time_ms DESC, id DESC)",
            "DROP INDEX CONCURRENTLY IF EXISTS public.actions_covenant_time_idx",
        ),
    ];
    for &(target, target_definition, replacement, replacement_definition, _) in PAIRS {
        let replacement_safe: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=to_regclass($1) AND indisvalid AND indisready AND indislive AND NOT indisunique AND NOT indisprimary AND pg_get_indexdef(indexrelid)=$2)",
        ).bind(replacement).bind(replacement_definition)
            .fetch_one(&mut *connection).await
            .context("validate action prefix replacement")?;
        anyhow::ensure!(replacement_safe,
            "action prefix replacement {replacement} lacks its required exact definition or readiness; preserving prefix indexes");
        let target_safe: bool = sqlx::query_scalar(
            "SELECT to_regclass($1) IS NULL OR EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=to_regclass($1) AND NOT indisunique AND NOT indisprimary AND pg_get_indexdef(indexrelid)=$2)",
        ).bind(target).bind(target_definition)
            .fetch_one(&mut *connection).await
            .context("validate action prefix retirement target")?;
        anyhow::ensure!(
            target_safe,
            "action prefix target {target} has an unexpected definition; preserving prefix indexes"
        );
    }
    for &(target, _, replacement, _, drop_sql) in PAIRS {
        sqlx::query(drop_sql)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("retiring redundant action prefix index {target}"))?;
        tracing::info!(
            target_index = target,
            replacement_index = replacement,
            "retired redundant action prefix index"
        );
    }
    Ok(())
}

async fn index_validity(connection: &mut PgConnection, name: &str) -> Result<Option<bool>> {
    sqlx::query_scalar(
        r#"
        SELECT i.indisvalid
        FROM pg_class c
        JOIN pg_index i ON i.indexrelid = c.oid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = $1
          AND n.nspname = ANY(current_schemas(false))
        "#,
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await
    .with_context(|| format!("checking index validity for {name}"))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn connection_error_omits_database_credentials() {
        let url = "postgres://diagnostic-user:diagnostic-password@localhost:invalid/db";
        let error = super::connect(url).await.unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(!diagnostic.contains(url));
        assert!(!diagnostic.contains("diagnostic-password"));
        assert!(!diagnostic.contains("diagnostic-user"));
    }

    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_migrators_serialize_without_deadlocking(pool: PgPool) {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (first, second) = tokio::join!(migrate(&pool), migrate(&pool));
            first.unwrap();
            second.unwrap();
        })
        .await
        .expect("concurrent migrators did not finish");
    }
}
