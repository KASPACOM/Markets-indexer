//! Isolated V2 runtime. No source URL or database defaults can target V1.
use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tn12_indexer_crawl::{durable_inbox::ChainAnchor, shadow_source::ShadowSource};
use tn12_indexer_db::{repo, shadow, PgPersister};

#[derive(Parser)]
struct Cli {
    #[arg(long, env = "SHADOW_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, env = "SHADOW_INSTANCE_ID")]
    instance_id: String,
    #[arg(long, default_value = "testnet-10")]
    network: String,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Provision an EMPTY database. Seed import and activation are separate.
    Init,
    /// Report durable progress. Never changes readiness or owns recovery.
    Status,
    /// Replay one checksum-verified archive plan without contacting a node.
    Replay {
        #[arg(long)]
        plan: std::path::PathBuf,
    },
    /// Follow the node's accepted chain using bounded pull requests.
    Run {
        #[arg(long, env = "SHADOW_WRPC_URL")]
        wrpc_url: String,
        #[arg(long, default_value_t = 10)]
        confirmations: u64,
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        #[arg(long, default_value_t = 8)]
        batch_blocks: usize,
        #[arg(long)]
        once: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    if matches!(cli.command, Command::Init) {
        return shadow::initialize(&cli.database_url, &cli.network, &cli.instance_id).await;
    }
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cli.database_url)
        .await?;
    shadow::verify(&pool, &cli.network, &cli.instance_id).await?;
    if !matches!(cli.command, Command::Status) {
        let revision = option_env!("SHADOW_DECODER_REVISION")
            .context("live/replay requires a binary built with SHADOW_DECODER_REVISION")?;
        shadow::verify_decoder(&pool, revision).await?;
    }
    match cli.command {
        Command::Status => {
            let value:Value=sqlx::query_scalar("SELECT to_jsonb(c)||jsonb_build_object('pending_steps',COALESCE(p.step_count-p.cursor,0),'plan_status',p.status) FROM shadow_v2.control c LEFT JOIN shadow_v2.plans p ON p.id=c.active_plan")
                .fetch_one(&pool).await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::Replay { plan } => {
            let activated: bool =
                sqlx::query_scalar("SELECT source_validated FROM shadow_v2.control")
                    .fetch_one(&pool)
                    .await?;
            ensure!(
                activated,
                "replay requires a seed activated by live source validation"
            );
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(plan)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "archive plan exceeds byte budget"
            );
            let archive: Value = serde_json::from_slice(&bytes)?;
            let revision = option_env!("SHADOW_DECODER_REVISION")
                .context("replay requires a binary built with SHADOW_DECODER_REVISION")?;
            ensure!(
                archive["format"] == "tn10-shadow-plan/1"
                    && archive["network"] == cli.network
                    && archive["instance_id"] == cli.instance_id
                    && archive["decoder_revision"] == revision,
                "archive format, network or decoder mismatch"
            );
            let archive_digest = tn12_indexer_core::blake2b_256(&bytes).to_vec();
            let already_complete:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM shadow_v2.plans WHERE archive_digest=$1 AND status='completed')")
                .bind(&archive_digest).fetch_one(&pool).await?;
            if already_complete {
                return Ok(());
            }
            let base = hex::decode(
                archive["base_hash"]
                    .as_str()
                    .context("missing archive base")?,
            )?;
            let target = hex::decode(
                archive["target_hash"]
                    .as_str()
                    .context("missing archive target")?,
            )?;
            let score = archive["target_score"]
                .as_i64()
                .context("missing archive target score")?;
            let mut tx = pool.begin().await?;
            let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire($1)")
                .bind(format!("archive-{}", std::process::id()))
                .fetch_one(&mut *tx)
                .await?;
            let existing: Option<i64> =
                sqlx::query_scalar("SELECT active_plan FROM shadow_v2.control")
                    .fetch_one(&mut *tx)
                    .await?;
            let plan = if let Some(plan) = existing {
                let matches:bool=sqlx::query_scalar("SELECT base_hash=$2 AND target_hash=$3 AND target_score=$4 AND (SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',kind,'evidence',evidence) ORDER BY ordinal),'[]'::jsonb) FROM shadow_v2.steps WHERE plan_id=$1)=$5 FROM shadow_v2.plans WHERE id=$1")
                    .bind(plan).bind(&base).bind(&target).bind(score).bind(&archive["steps"]).fetch_one(&mut *tx).await?;
                ensure!(matches, "active recovery differs from archive plan");
                plan
            } else {
                sqlx::query_scalar(
                    "SELECT shadow_v2.begin_plan($1,$2,$3,$4,ARRAY['ingestor','projection'],$5)",
                )
                .bind(epoch)
                .bind(base)
                .bind(target)
                .bind(score)
                .bind(&archive["steps"])
                .fetch_one(&mut *tx)
                .await?
            };
            sqlx::query("UPDATE shadow_v2.plans SET archive_digest=$2 WHERE id=$1 AND (archive_digest IS NULL OR archive_digest=$2)")
                .bind(plan).bind(archive_digest).execute(&mut *tx).await?;
            tx.commit().await?;
            apply_plan(&cli.database_url, &pool, &cli.network, epoch, plan).await?;
        }
        Command::Run {
            wrpc_url,
            confirmations,
            poll_ms,
            batch_blocks,
            once,
        } => {
            ensure!(
                (100..=60_000).contains(&poll_ms),
                "poll-ms must be 100..60000"
            );
            ensure!(
                (1..=16).contains(&batch_blocks),
                "batch-blocks must be 1..16"
            );
            let owner = format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
            );
            let mut delay = poll_ms;
            loop {
                // Cancellation drops any in-flight SQL transaction; durable plans
                // remain unavailable until a new owner verifies and resumes them.
                let outcome = tokio::select! {
                    result=cycle(&cli.database_url,&pool,&owner,&cli.network,&wrpc_url,confirmations,batch_blocks)=>result,
                    _=tokio::signal::ctrl_c()=>break,
                };
                match outcome {
                    Ok(()) => delay = poll_ms,
                    Err(error) => {
                        if once {
                            return Err(error);
                        }
                        tracing::error!(error=%format!("{error:#}"),"shadow cycle stopped; durable cursor retained");
                        delay = (delay * 2).min(30_000);
                    }
                }
                if once {
                    break;
                }
                tokio::select! { _=tokio::time::sleep(Duration::from_millis(delay))=>{}, _=tokio::signal::ctrl_c()=>break }
            }
        }
        Command::Init => unreachable!(),
    }
    pool.close().await;
    Ok(())
}

async fn cycle(
    url: &str,
    pool: &PgPool,
    owner: &str,
    network: &str,
    endpoint: &str,
    confirmations: u64,
    batch_blocks: usize,
) -> Result<()> {
    let (active, hash, score, ready): (Option<i64>, Vec<u8>, i64, bool) = sqlx::query_as(
        "SELECT active_plan,checkpoint_hash,checkpoint_score,ready FROM shadow_v2.control",
    )
    .fetch_one(pool)
    .await?;
    let prepared = if active.is_none() {
        let mut source = ShadowSource::connect(endpoint, network).await?;
        let prepared = source
            .prepare(
                &ChainAnchor {
                    network: network.into(),
                    block_hash: hex::encode(&hash),
                    blue_score: u64::try_from(score)?,
                },
                confirmations,
                batch_blocks,
            )
            .await?;
        sqlx::query("UPDATE shadow_v2.control SET source_checked_at=clock_timestamp()")
            .execute(pool)
            .await?;
        match prepared {
            Some(plan) => Some(plan),
            None if !ready => Some(tn12_indexer_crawl::shadow_source::ShadowPlan {
                target: ChainAnchor {
                    network: network.into(),
                    block_hash: hex::encode(&hash),
                    blue_score: u64::try_from(score)?,
                },
                steps: serde_json::json!([]),
            }),
            None => return Ok(()),
        }
    } else {
        None
    };
    let mut coordination = pool.begin().await?;
    let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire($1)")
        .bind(owner)
        .fetch_one(&mut *coordination)
        .await?;
    let unchanged: bool = sqlx::query_scalar(
        "SELECT active_plan IS NOT DISTINCT FROM $1 AND checkpoint_hash=$2 FROM shadow_v2.control",
    )
    .bind(active)
    .bind(&hash)
    .fetch_one(&mut *coordination)
    .await?;
    ensure!(
        unchanged,
        "shadow checkpoint changed while preparing source window"
    );
    let plan = if let Some(id) = active {
        id
    } else {
        let prepared = prepared.context("missing prepared shadow plan")?;
        sqlx::query_scalar(
            "SELECT shadow_v2.begin_plan($1,$2,$3,$4,ARRAY['ingestor','projection'],$5)",
        )
        .bind(epoch)
        .bind(&hash)
        .bind(hex::decode(&prepared.target.block_hash)?)
        .bind(i64::try_from(prepared.target.blue_score)?)
        .bind(prepared.steps)
        .fetch_one(&mut *coordination)
        .await?
    };
    if active.is_some() {
        let validated: bool = sqlx::query_scalar("SELECT source_validated FROM shadow_v2.control")
            .fetch_one(&mut *coordination)
            .await?;
        ensure!(validated, "unfinished plan has no live seed validation");
    } else {
        sqlx::query("UPDATE shadow_v2.control SET source_validated=true")
            .execute(&mut *coordination)
            .await?;
    }
    coordination.commit().await?;
    apply_plan(url, pool, network, epoch, plan).await
}

async fn apply_plan(url: &str, pool: &PgPool, network: &str, epoch: i64, plan: i64) -> Result<()> {
    let (status, cursor, count): (String, i64, i64) =
        sqlx::query_as("SELECT status,cursor,step_count FROM shadow_v2.plans WHERE id=$1")
            .bind(plan)
            .fetch_one(pool)
            .await?;
    // A crash after seal needs no reapplication. Acquire preserves the seal.
    if status != "sealed" {
        let writer_pool = shadow::writer_pool(url, epoch, plan).await?;
        let writer = PgPersister::for_wrpc(writer_pool.clone(), network.to_owned())?
            .with_bounded_writer_lock_wait();
        for ordinal in cursor..count {
            writer.apply_shadow_step(epoch, plan, ordinal).await?;
        }
        project(&writer_pool).await?;
        // Stop public-table mutations before verification and publication.
        writer_pool.close().await;
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT shadow_v2.fence($1,$2)")
            .bind(epoch)
            .bind(plan)
            .execute(&mut *tx)
            .await?;
        let inconsistent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE u.status='active' AND (u.spent_block IS NOT NULL OR u.spent_by_txid IS NOT NULL OR NOT b.is_chain_block))")
            .fetch_one(&mut *tx).await?;
        ensure!(!inconsistent, "active UTXO invariants failed");
        // These are the two sequential consumers in this runtime; neither is
        // advanced by publication itself.
        for consumer in ["ingestor", "projection"] {
            sqlx::query("SELECT shadow_v2.consumer_done($1,$2,$3)")
                .bind(epoch)
                .bind(plan)
                .bind(consumer)
                .execute(&mut *tx)
                .await?;
        }
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM shadow_v2.control")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("SELECT shadow_v2.publish($1,$2,$3)")
            .bind(epoch)
            .bind(plan)
            .bind(revision)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    sqlx::query("SELECT shadow_v2.release($1,$2)")
        .bind(epoch)
        .bind(plan)
        .execute(pool)
        .await?;
    tracing::info!(epoch, plan, steps = count, "shadow generation published");
    Ok(())
}

async fn project(pool: &PgPool) -> Result<()> {
    let target = repo::capture_kcc20_projection_pass_dirty_id(&mut *pool.acquire().await?).await?;
    // Existing projection implementations operate on the isolated shadow DB.
    // Their actual writes are guarded even across internal transaction boundaries.
    repo::initialize_kcc20_owner_action_backfill(pool).await?;
    let mut complete = false;
    for _ in 0..4096 {
        if repo::backfill_kcc20_owner_action_history_batch(pool, 500).await? {
            complete = true;
            break;
        }
    }
    ensure!(
        complete,
        "owner history backfill pass budget exceeded; resume required"
    );
    loop {
        let stats = repo::refresh_kcc20_activity_feed_with_config(
            pool,
            repo::Kcc20ActivityFeedRefreshConfig::projector(target, true, "30s".into()),
        )
        .await?;
        if stats.last_dirty_id >= target {
            break;
        }
        ensure!(stats.dirty_rows > 0, "activity projection did not advance");
    }
    repo::refresh_kcc20_owner_orders(pool).await?;
    repo::refresh_kcc20_market_summaries(pool).await?;
    repo::refresh_kcc20_token_page_projections(pool).await?;
    repo::refresh_kcc20_owner_portfolio_assets(pool).await?;
    for name in [
        "owner_orders",
        "market",
        "token_page",
        "owner_portfolio_assets",
    ] {
        repo::mark_kcc20_projection_refreshed_for(pool, name, target).await?;
    }
    for _ in 0..4096 {
        repo::refresh_kcc20_owner_action_history(pool, target, 500).await?;
        let ready:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kcc20_owner_action_backfill b JOIN kcc20_projection_state p ON p.name='owner_action_history' WHERE b.singleton AND b.ready AND p.last_dirty_id >= $1)")
            .bind(target).fetch_one(pool).await?;
        if ready {
            return Ok(());
        }
        repo::backfill_kcc20_owner_action_history_batch(pool, 500).await?;
    }
    anyhow::bail!("owner history projection pass budget exceeded; resume required")
}
