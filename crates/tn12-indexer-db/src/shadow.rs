//! Opt-in shadow database lifecycle. Never called by V1 migrations or workers.
use anyhow::{ensure, Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

pub const MIGRATION: &str = include_str!("../shadow-migrations/001_coordination.sql");

pub async fn initialize(url: &str, network: &str, instance_id: &str) -> Result<()> {
    ensure!(
        network == "testnet-10",
        "initial shadow release supports TN10 only"
    );
    let pool = PgPoolOptions::new().max_connections(2).connect(url).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname IN ('public','shadow_v2'))",
    )
    .fetch_one(&pool)
    .await?;
    ensure!(
        !exists,
        "shadow initialization requires an empty dedicated database"
    );
    // Explicit initialization owns both schema phases. Normal startup never migrates.
    crate::migrate(&pool).await?;
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(MIGRATION).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO shadow_v2.identity(network,instance_id) VALUES($1,$2::text::uuid)")
        .bind(network)
        .bind(instance_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT shadow_v2.install_guards()")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    pool.close().await;
    Ok(())
}

pub async fn verify(pool: &PgPool, network: &str, instance_id: &str) -> Result<()> {
    let identity: (String, String, i32) =
        sqlx::query_as("SELECT network,instance_id::text,format_version FROM shadow_v2.identity")
            .fetch_one(pool)
            .await
            .context("database is not initialized for shadow V2")?;
    ensure!(
        identity.0 == network && identity.1 == instance_id && identity.2 == 1,
        "shadow database identity mismatch"
    );
    let recorded: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version,checksum FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(pool)
    .await?;
    let migrations = sqlx::migrate!("./migrations");
    ensure!(
        recorded.len() == migrations.migrations.len()
            && recorded.iter().zip(migrations.migrations.iter()).all(
                |((version, checksum), migration)| *version == migration.version
                    && checksum.as_slice() == migration.checksum.as_ref()
            ),
        "shadow base schema differs from this binary; explicit migration required"
    );
    let unguarded:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_tables t WHERE t.schemaname='public' AND t.tablename<>'_sqlx_migrations' AND NOT EXISTS(SELECT 1 FROM shadow_v2.guarded_tables g WHERE g.table_name=t.tablename AND (SELECT count(*) FROM pg_trigger tr JOIN pg_class cl ON cl.oid=tr.tgrelid JOIN pg_namespace ns ON ns.oid=cl.relnamespace WHERE ns.nspname='public' AND cl.relname=t.tablename AND tr.tgname IN ('shadow_v2_guard','shadow_v2_write','shadow_v2_truncate') AND tr.tgenabled='O')=3))")
        .fetch_one(pool).await?;
    ensure!(
        !unguarded,
        "shadow seed is not activated or schema guard inventory changed"
    );
    let seeded: bool = sqlx::query_scalar(
        "SELECT checkpoint_hash IS NOT NULL AND seed_manifest IS NOT NULL FROM shadow_v2.control",
    )
    .fetch_one(pool)
    .await?;
    ensure!(seeded, "shadow database has no verified seed");
    Ok(())
}

/// Separate bounded pool for one immutable ownership epoch and plan. Guards
/// check these session settings inside every transaction, including projectors.
pub async fn writer_pool(url: &str, epoch: i64, plan: i64) -> Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(4).acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn,_|Box::pin(async move {
            sqlx::query("SELECT set_config('shadow_v2.epoch',$1,false),set_config('shadow_v2.plan',$2,false),set_config('statement_timeout','30s',false),set_config('lock_timeout','5s',false)")
                .bind(epoch.to_string()).bind(plan.to_string()).execute(conn).await?;
            Ok(())
        })).connect(url).await?)
}

/// Decoder identity is a reviewed compatibility identity, not a caller-provided
/// runtime override. Both seed provenance fields must match the compiled pin.
pub async fn verify_decoder(pool: &PgPool, revision: &str) -> Result<()> {
    ensure!(!revision.is_empty(), "empty SHADOW_DECODER_REVISION");
    let matches: bool = sqlx::query_scalar("SELECT COALESCE(seed_manifest->>'decoder_revision'=$1 AND seed_manifest->'source_identity'->>'decoder_revision'=$1 AND seed_manifest->'source_identity'->>'genesis_hash'='f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',false) FROM shadow_v2.control")
        .bind(revision).fetch_one(pool).await?;
    ensure!(matches, "seed decoder revision or TN10 genesis mismatch");
    Ok(())
}
