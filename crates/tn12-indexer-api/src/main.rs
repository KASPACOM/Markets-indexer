//! HTTP API for KaspaCom Covenant Tools.
//!
//! The API can serve local fixture-backed state from an in-memory
//! `IndexerEngine`, or live scanner state from Postgres when `DATABASE_URL` is
//! set.

#![recursion_limit = "512"]

mod shadow;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::{
    body::{Body, Bytes},
    extract::{MatchedPath, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use kaspa_addresses::{Address, Prefix, Version};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use tn12_indexer_core::{
    blake2b_256, ApiPaymentChannelCloseRequest, ApiPaymentChannelCloseRequestExpectation,
    RestTransaction,
};
use tn12_indexer_crawl::source_observation::{
    spawn_node_observer, spawn_rest_observer, SharedNodeObservation, SharedRestObservation,
};
use tn12_indexer_crawl::{CovenantEvent, EngineSnapshot, IndexerEngine, RestClient};
use tn12_indexer_db::{
    api_payments as db_api_payments, connect as db_connect, is_transient_persist_error,
    migrate as db_migrate, repo, PersistStats, Persister, PgPersister,
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use utoipa_swagger_ui::SwaggerUi;

mod api_payments;
mod openapi;
mod settled_recheck;
mod recovery_health;
mod sync_queue;

static NEXT_HTTP_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

const MAX_ORDERBOOK_DEPTH_LIMIT: usize = 1000;
const DEFAULT_ORDERBOOK_DEPTH_LIMIT: usize = 100;
const SCANNER_HEALTH_MAX_CURSOR_AGE_MS: i64 = 15_000;
const SCANNER_HEALTH_MAX_DB_CURSOR_LAG_BLOCKS: i64 = 500;
const LIVE_MAX_SOURCE_LAG_SCORES: i64 = 100;

#[derive(Parser, Debug)]
#[command(name = "covenant-tools-api")]
#[command(about = "HTTP API serving indexed covenant state")]
struct Cli {
    /// Enable read-only shadow serving for this exact database instance.
    #[arg(long, env = "SHADOW_INSTANCE_ID")]
    shadow_instance_id: Option<String>,
    /// Directory of captured REST transaction JSON files to replay on startup.
    #[arg(long)]
    fixture_dir: Option<PathBuf>,
    /// Postgres connection URL. If set, replayed transactions are persisted
    /// to the DB in addition to the in-memory snapshot. Env: DATABASE_URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Historical replay database during a split TN10 recovery.
    #[arg(long, env = "HISTORY_DATABASE_URL", hide_env_values = true)]
    history_database_url: Option<String>,
    /// Independent chain progress source. Env: KASPA_WRPC_URL.
    #[arg(long, env = "KASPA_WRPC_URL")]
    kaspa_wrpc_url: Option<String>,
    /// Run `sqlx migrate run` at startup when --database-url is set.
    #[arg(long, default_value_t = false)]
    migrate: bool,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:8081")]
    bind: String,
    /// Enforce API payment policy on priced routes. Env: API_PAYMENTS_ENABLED.
    #[arg(long, env = "API_PAYMENTS_ENABLED", default_value_t = false)]
    api_payments_enabled: bool,
    /// Emergency rollback switch: serve priced routes as free/read-only even
    /// when API_PAYMENTS_ENABLED is true. Env: API_PAYMENTS_ROLLBACK_FREE.
    #[arg(long, env = "API_PAYMENTS_ROLLBACK_FREE", default_value_t = false)]
    api_payments_rollback_free: bool,
    /// Network id used in payment challenges. Env: API_PAYMENT_NETWORK_ID.
    #[arg(long, env = "API_PAYMENT_NETWORK_ID", default_value = "testnet-10")]
    api_payment_network_id: String,
    /// Price for the built-in API payment proof discovery route in sompi.
    /// Env: API_PAYMENT_KCC20_DISCOVERY_SOMPI.
    #[arg(
        long,
        env = "API_PAYMENT_KCC20_DISCOVERY_SOMPI",
        default_value_t = 50_000_000
    )]
    api_payment_kcc20_discovery_sompi: u64,
    /// Comma/newline separated paid route allowlist. Unset keeps configured priced routes; empty disables route enforcement. Env: API_PAYMENT_PAID_ROUTES.
    #[arg(long, env = "API_PAYMENT_PAID_ROUTES")]
    api_payment_paid_routes: Option<String>,
    /// Reject channel vouchers this close to refundAfterMs. Env: API_PAYMENT_REFUND_SAFETY_MARGIN_MS.
    #[arg(
        long,
        env = "API_PAYMENT_REFUND_SAFETY_MARGIN_MS",
        default_value_t = 300_000
    )]
    api_payment_refund_safety_margin_ms: u64,
    /// Recipient address for client-broadcast direct API payments. Env: API_PAYMENT_DIRECT_RECIPIENT_ADDRESS.
    #[arg(long, env = "API_PAYMENT_DIRECT_RECIPIENT_ADDRESS")]
    api_payment_direct_recipient_address: Option<String>,
    /// REST URL used to verify client-broadcast direct payment txids. Env: API_PAYMENT_REST_URL.
    #[arg(long, env = "API_PAYMENT_REST_URL")]
    api_payment_rest_url: Option<String>,
    /// Chain REST URL used for payment tx sync/verification fallback. Env: KASPA_REST_URL.
    #[arg(long, env = "KASPA_REST_URL")]
    kaspa_rest_url: Option<String>,
    /// Comma/newline separated backup REST URLs used only for direct tx lookup.
    /// Env: KASPA_REST_FALLBACK_URLS.
    #[arg(long, env = "KASPA_REST_FALLBACK_URLS")]
    kaspa_rest_fallback_urls: Option<String>,
    /// Optional bearer token required by POST /payments/channels/{channelId}/sync.
    /// Env: API_PAYMENT_CHANNEL_SYNC_BEARER_TOKEN.
    #[arg(
        long,
        env = "API_PAYMENT_CHANNEL_SYNC_BEARER_TOKEN",
        hide_env_values = true
    )]
    api_payment_channel_sync_bearer_token: Option<String>,
    /// Process-local max POST /payments/channels/{channelId}/sync requests per minute.
    /// Env: API_PAYMENT_CHANNEL_SYNC_MAX_PER_MINUTE.
    #[arg(
        long,
        env = "API_PAYMENT_CHANNEL_SYNC_MAX_PER_MINUTE",
        default_value_t = 60
    )]
    api_payment_channel_sync_max_per_minute: u64,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<EngineHolder>>,
    persister: Option<Arc<PgPersister>>,
    history_pool: Option<PgPool>,
    history_progress: Arc<Mutex<Option<HistoryProgressSample>>>,
    source_observation: SharedNodeObservation,
    rest_publication: SharedRestObservation,
    network_id: String,
    payment_policy: Arc<api_payments::ApiPaymentPolicyCatalog>,
    direct_payment_rest: Option<RestClient>,
    payment_metrics: Arc<ApiPaymentRuntimeMetrics>,
    http_metrics: Arc<HttpRequestMetrics>,
    channel_sync_guard: Arc<ApiPaymentChannelSyncGuard>,
}

const HTTP_DURATION_BUCKETS_SECONDS: [f64; 8] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0];

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct HttpMetricKey {
    method: String,
    route: String,
    status_class: String,
}

#[derive(Debug, Default)]
struct HttpMetricValue {
    count: u64,
    duration_sum_seconds: f64,
    duration_buckets: [u64; HTTP_DURATION_BUCKETS_SECONDS.len()],
}

#[derive(Debug, Default)]
struct HttpRequestMetrics {
    values: Mutex<BTreeMap<HttpMetricKey, HttpMetricValue>>,
}

impl HttpRequestMetrics {
    fn record(&self, method: &str, route: &str, status: StatusCode, duration_seconds: f64) {
        let status_class = format!("{}xx", status.as_u16() / 100);
        let key = HttpMetricKey {
            method: method.to_string(),
            route: route.to_string(),
            status_class,
        };
        let Ok(mut values) = self.values.lock() else {
            tracing::error!("HTTP request metrics lock is poisoned");
            return;
        };
        let value = values.entry(key).or_default();
        value.count = value.count.saturating_add(1);
        value.duration_sum_seconds += duration_seconds;
        for (index, upper_bound) in HTTP_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if duration_seconds <= *upper_bound {
                value.duration_buckets[index] = value.duration_buckets[index].saturating_add(1);
            }
        }
    }

    fn render(&self) -> String {
        let Ok(values) = self.values.lock() else {
            tracing::error!("HTTP request metrics lock is poisoned");
            return String::new();
        };
        let mut output = String::new();
        output.push_str(
            "# HELP tn10_indexer_http_requests_total HTTP requests by route and status class.\n",
        );
        output.push_str("# TYPE tn10_indexer_http_requests_total counter\n");
        output.push_str("# HELP tn10_indexer_http_request_duration_seconds HTTP request duration by route and status class.\n");
        output.push_str("# TYPE tn10_indexer_http_request_duration_seconds histogram\n");
        for (key, value) in values.iter() {
            let labels = format!(
                "method=\"{}\",route=\"{}\",status_class=\"{}\"",
                prometheus_label_value(&key.method),
                prometheus_label_value(&key.route),
                prometheus_label_value(&key.status_class)
            );
            let _ = writeln!(
                output,
                "tn10_indexer_http_requests_total{{{labels}}} {}",
                value.count
            );
            for (index, upper_bound) in HTTP_DURATION_BUCKETS_SECONDS.iter().enumerate() {
                let _ = writeln!(
                    output,
                    "tn10_indexer_http_request_duration_seconds_bucket{{{labels},le=\"{upper_bound}\"}} {}",
                    value.duration_buckets[index]
                );
            }
            let _ = writeln!(
                output,
                "tn10_indexer_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}",
                value.count
            );
            let _ = writeln!(
                output,
                "tn10_indexer_http_request_duration_seconds_sum{{{labels}}} {}",
                value.duration_sum_seconds
            );
            let _ = writeln!(
                output,
                "tn10_indexer_http_request_duration_seconds_count{{{labels}}} {}",
                value.count
            );
        }
        output
    }
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Default)]
struct ApiPaymentRuntimeMetrics {
    paid_requests_served: AtomicU64,
    authorization_failures: AtomicU64,
    receipt_record_failures: AtomicU64,
    receipt_encode_failures: AtomicU64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiPaymentRuntimeMetricsSnapshot {
    paid_requests_served: u64,
    authorization_failures: u64,
    receipt_record_failures: u64,
    receipt_encode_failures: u64,
}

struct ApiPaymentChannelSyncGuard {
    bearer_token: Option<String>,
    max_per_minute: u64,
    window_minute: AtomicU64,
    window_count: AtomicU64,
}

impl ApiPaymentRuntimeMetrics {
    fn snapshot(&self) -> ApiPaymentRuntimeMetricsSnapshot {
        ApiPaymentRuntimeMetricsSnapshot {
            paid_requests_served: self.paid_requests_served.load(Ordering::Relaxed),
            authorization_failures: self.authorization_failures.load(Ordering::Relaxed),
            receipt_record_failures: self.receipt_record_failures.load(Ordering::Relaxed),
            receipt_encode_failures: self.receipt_encode_failures.load(Ordering::Relaxed),
        }
    }
}

impl ApiPaymentChannelSyncGuard {
    fn new(bearer_token: Option<String>, max_per_minute: u64) -> Self {
        Self {
            bearer_token: bearer_token.filter(|token| !token.trim().is_empty()),
            max_per_minute,
            window_minute: AtomicU64::new(0),
            window_count: AtomicU64::new(0),
        }
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), Response> {
        let Some(expected) = self.bearer_token.as_deref() else {
            return Ok(());
        };
        let bearer = headers
            .get(api_payments::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim);
        let sync_header = headers
            .get("x-api-payment-sync-token")
            .and_then(|value| value.to_str().ok())
            .map(str::trim);
        if bearer
            .or(sync_header)
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
        {
            return Ok(());
        }
        Err(direct_payment_problem(
            StatusCode::UNAUTHORIZED,
            "payment-channel-sync-unauthorized",
            "Payment Channel Sync Unauthorized",
            Some("valid sync bearer token is required"),
        ))
    }

    fn try_acquire(&self, now_ms: u64) -> bool {
        if self.max_per_minute == 0 {
            return true;
        }
        let minute = now_ms / 60_000;
        let current = self.window_minute.load(Ordering::Relaxed);
        if current != minute
            && self
                .window_minute
                .compare_exchange(current, minute, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.window_count.store(0, Ordering::Relaxed);
        }
        loop {
            let count = self.window_count.load(Ordering::Relaxed);
            if count >= self.max_per_minute {
                return false;
            }
            if self
                .window_count
                .compare_exchange(count, count + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kcc20OwnerLookup {
    OwnerIdentifierHex(String),
    CovenantAddress(String),
}

struct EngineHolder {
    engine: IndexerEngine,
    events: Vec<CovenantEvent>,
}

impl EngineHolder {
    fn new() -> Self {
        Self {
            engine: IndexerEngine::new(),
            events: Vec::new(),
        }
    }

    fn ingest(&mut self, tx: &RestTransaction) -> Result<()> {
        let mut events = self.engine.process_tx(tx)?;
        self.events.append(&mut events);
        Ok(())
    }

    fn snapshot(&self) -> EngineSnapshot {
        self.engine.snapshot(&self.events)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    if cli.shadow_instance_id.is_some() {
        anyhow::ensure!(!cli.migrate && cli.fixture_dir.is_none() && !cli.api_payments_enabled
            && cli.history_database_url.is_none() && cli.kaspa_rest_url.is_none()
            && cli.api_payment_rest_url.is_none() && cli.kaspa_wrpc_url.is_none(),
            "shadow API forbids migrations, fixtures, payments and external/history sources");
    }
    let persister = if let Some(url) = cli.database_url.as_deref() {
        let pool = db_connect(url).await.context("connect db")?;
        let is_shadow: bool = sqlx::query_scalar("SELECT to_regnamespace('shadow_v2') IS NOT NULL")
            .fetch_one(&pool).await?;
        anyhow::ensure!(!is_shadow || cli.shadow_instance_id.is_some(), "marked shadow database requires --shadow-instance-id");
        if cli.migrate {
            db_migrate(&pool).await.context("run migrations")?;
            tracing::info!("ran sqlx migrations");
        }
        tracing::info!("persisting to {}", redact_url(url));
        // Queue direct sync writes behind the live writer's short transaction.
        // A try-lock collision would reject an otherwise valid live transaction.
        Some(Arc::new(
            PgPersister::with_network_id(pool, cli.api_payment_network_id.clone())
                .with_bounded_writer_lock_wait(),
        ))
    } else {
        None
    };
    let shadow_api = if let Some(instance) = cli.shadow_instance_id.as_deref() {
        let pool = persister.as_ref().context("shadow API requires an explicit database")?.pool().clone();
        tn12_indexer_db::shadow::verify(&pool, &cli.api_payment_network_id, instance).await?;
        tn12_indexer_db::shadow::verify_decoder(&pool, option_env!("SHADOW_DECODER_REVISION")
            .ok_or_else(|| anyhow::anyhow!("shadow API requires compiled SHADOW_DECODER_REVISION"))?).await?;
        Some(shadow::ShadowApi::new(pool)?)
    } else { None };
    let history_pool = match cli.history_database_url.as_deref() {
        Some(url) => Some(db_connect(url).await.context("connect history db")?),
        None => None,
    };

    let api_payments_enforced = api_payments_enforced(&cli);
    if cli.api_payments_enabled && cli.api_payments_rollback_free {
        tracing::warn!(
            "API payment enforcement disabled by API_PAYMENTS_ROLLBACK_FREE rollback switch"
        );
    }

    let mut payment_policy = api_payments::ApiPaymentPolicyCatalog::new(
        api_payments_enforced,
        cli.api_payment_network_id.clone(),
        cli.api_payment_kcc20_discovery_sompi,
    )
    .with_refund_safety_margin_ms(cli.api_payment_refund_safety_margin_ms);
    if let Some(persister) = persister.as_ref() {
        match db_api_payments::api_payment_pricing_routes(persister.pool(), now_ms() as i64).await {
            Ok(rows) if !rows.is_empty() => {
                tracing::info!(
                    count = rows.len(),
                    "loaded API payment pricing rows from DB"
                );
                payment_policy = payment_policy.with_pricing_rows(rows);
            }
            Ok(_) => {
                tracing::warn!("API payment pricing table has no active rows; using CLI fallback");
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to load API payment pricing rows; using CLI fallback");
            }
        }
    }
    payment_policy =
        payment_policy.with_paid_route_allowlist(cli.api_payment_paid_routes.as_deref());
    payment_policy =
        payment_policy.with_direct_recipient(cli.api_payment_direct_recipient_address.clone());

    let state = AppState {
        inner: Arc::new(RwLock::new(EngineHolder::new())),
        persister,
        history_pool,
        history_progress: Arc::new(Mutex::new(None)),
        source_observation: Arc::new(Mutex::new(None)),
        rest_publication: Arc::new(Mutex::new(None)),
        network_id: cli.api_payment_network_id.clone(),
        payment_policy: Arc::new(payment_policy),
        direct_payment_rest: cli
            .api_payment_rest_url
            .clone()
            .or_else(|| cli.kaspa_rest_url.clone())
            .map(|url| {
                RestClient::new(url).map(|client| {
                    client
                        .with_fallback_urls(parse_list_env(cli.kaspa_rest_fallback_urls.as_deref()))
                })
            })
            .transpose()
            .context("build payment REST client")?,
        payment_metrics: Arc::new(ApiPaymentRuntimeMetrics::default()),
        http_metrics: Arc::new(HttpRequestMetrics::default()),
        channel_sync_guard: Arc::new(ApiPaymentChannelSyncGuard::new(
            cli.api_payment_channel_sync_bearer_token.clone(),
            cli.api_payment_channel_sync_max_per_minute,
        )),
    };

    let _sync_queue_consumer = if shadow_api.is_none() { Some(sync_queue::spawn(state.clone())) } else { None };

    let _source_observer = cli
        .kaspa_wrpc_url
        .as_deref()
        .map(|url| spawn_node_observer(url, &state.network_id, state.source_observation.clone()))
        .transpose()
        .context("start independent node observer")?;

    let _rest_observer = cli
        .kaspa_rest_url
        .as_ref()
        .map(|url| {
            RestClient::new(url).map(|client| {
                spawn_rest_observer(
                    client,
                    state.network_id.clone(),
                    state.rest_publication.clone(),
                )
            })
        })
        .transpose()
        .context("start REST publication observer")?;

    if let Some(dir) = cli.fixture_dir.as_ref() {
        replay_fixture_dir(&state, dir).await?;
    }

    let swagger = Router::<AppState>::from(
        SwaggerUi::new("/swagger-ui").external_url_unchecked("/openapi.json", openapi::spec()),
    );

    let http_metrics = Arc::clone(&state.http_metrics);
    let app = Router::new()
        .merge(swagger)
        .route("/swagger", get(swagger_redirect))
        .route("/docs", get(swagger_redirect))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/history", get(health_history))
        .route("/metrics", get(metrics))
        .route("/explorer/summary", get(explorer_summary))
        .route("/explorer/search", get(explorer_search))
        .route("/payments/pricing", get(payments_pricing))
        .route("/payments/metrics", get(payments_metrics))
        .route("/payments/debug", get(payments_debug_ui))
        .route("/payments/challenges", post(payments_challenge))
        .route("/payments/direct-proofs", post(payments_direct_proof))
        .route(
            "/payments/direct-proofs/{txid}",
            get(payments_direct_proof_status),
        )
        .route(
            "/payments/direct-proofs/{txid}/verify",
            post(payments_direct_proof_verify),
        )
        .route(
            "/payments/receipts/{receipt_id}",
            get(payments_receipt_status),
        )
        .route(
            "/payments/channels/{channel_id}",
            get(payments_channel_status),
        )
        .route(
            "/payments/channels/{channel_id}/sync",
            post(payments_channel_sync),
        )
        .route(
            "/payments/channels/{channel_id}/close",
            post(payments_channel_close),
        )
        .route(
            "/payments/settlements/{txid}",
            get(payments_settlement_status),
        )
        .route("/snapshot", get(snapshot))
        .route("/utxos", get(list_active_utxos))
        .route("/covenant-templates", get(covenant_templates))
        .route("/covenants", get(list_covenants))
        .route("/covenants/by-id/{script_hash}", get(covenant_detail))
        .route(
            "/covenants/by-id/{script_hash}/actions",
            get(covenant_actions),
        )
        .route("/covenants/by-id/{script_hash}/utxos", get(covenant_utxos))
        .route("/covenants/{script_hash}", get(covenant_detail))
        .route("/covenants/{script_hash}/actions", get(covenant_actions))
        .route("/covenants/{script_hash}/utxos", get(covenant_utxos))
        .route("/kcom/campaigns/{graph_id}", get(kcom_campaign))
        .route("/kcom/campaigns/{graph_id}/participants/{authority}", get(kcom_participant))
        .route("/addresses/{address}/covenants", get(covenants_for_address))
        .route("/addresses/{address}/utxos", get(utxos_for_address))
        .route("/addresses/{address}/events", get(events_for_address))
        .route("/fomo/rounds", get(fomo_rounds))
        .route("/fomo/rounds/{covenant_id}", get(fomo_round_detail))
        .route("/kcc20/wrappers", get(kcc20_wrappers))
        .route(
            "/kcc20/fee-markets/by-canonical/{covenant_id}",
            get(kcc20_fee_markets_by_canonical),
        )
        .route("/kcc20/fee-markets/{market_id}/receipts", get(kcc20_fee_receipts))
        .route(
            "/kcc20/snapshot/controllers/{controller_id}/claims/{token_id}",
            get(kcc20_snapshot_claims),
        )
        .route("/kcc20/{covenant_id}/summary", get(kcc20_token_summary))
        .route(
            "/kcc20/wrappers/by-canonical/{covenant_id}",
            get(kcc20_wrappers_by_canonical),
        )
        .route("/kcc20/{covenant_id}/holders", get(kcc20_holders))
        .route("/kcc20/{covenant_id}/utxos", get(kcc20_utxos))
        .route("/kcc20/freshness", get(kcc20_freshness))
        .route("/kcc20/markets", get(kcc20_markets))
        .route("/kcc20/discovery", get(kcc20_discovery))
        .route(
            "/payments/proof/kcc20-discovery",
            get(payment_proof_kcc20_discovery),
        )
        .route("/payments/proof/body-echo", post(payment_proof_body_echo))
        .route("/kcc20/market-snapshots", get(kcc20_market_snapshots))
        .route(
            "/kcc20/{covenant_id}/orderbook",
            get(kcc20_orderbook_for_token),
        )
        .route("/kcc20/{covenant_id}/stats", get(kcc20_stats_for_token))
        .route("/kcc20/{covenant_id}/candles", get(kcc20_candles_for_token))
        .route(
            "/kcc20/{covenant_id}/activity",
            get(kcc20_activity_for_token),
        )
        .route("/kcc20/{covenant_id}/quote", get(kcc20_quote_for_token))
        .route(
            "/kcc20/{covenant_id}/orders/{order_id}",
            get(kcc20_order_detail_for_token),
        )
        .route(
            "/kcc20/{covenant_id}/listings",
            get(kcc20_listings_for_token),
        )
        .route("/kcc20/{covenant_id}/bids", get(kcc20_bids_for_token))
        .route("/kcc20/listings", get(kcc20_listings))
        .route("/kcc20/bids", get(kcc20_bids))
        .route("/kcc20/{covenant_id}/trades", get(kcc20_trades_for_token))
        .route(
            "/addresses/{address}/kcc20/orders",
            get(kcc20_orders_for_address),
        )
        .route(
            "/addresses/{address}/kcc20/balances",
            get(kcc20_balances_for_address),
        )
        .route(
            "/addresses/{address}/kcc20/portfolio",
            get(kcc20_portfolio_for_address),
        )
        .route(
            "/addresses/{address}/kcc20/portfolio-assets",
            get(kcc20_portfolio_assets_for_address),
        )
        .route(
            "/addresses/{address}/kcc20/trades",
            get(kcc20_trades_for_address),
        )
        .route(
            "/addresses/{address}/kcc20/actions",
            get(kcc20_actions_for_address),
        )
        .route("/tx/{txid}/settlement-status", get(tx_settlement_status))
        .route("/events", get(list_events))
        .route("/tx/{txid}", get(events_by_txid))
        .layer(middleware::from_fn_with_state(state.clone(),decode_coverage_headers))
        .layer(middleware::from_fn_with_state(state.clone(), recovery_read_fence))
        // Receipt of a sync request is permitted during canonical recovery;
        // tx_sync applies the fence separately before and after canonical work.
        .route("/tx/{txid}/sync", post(tx_sync).layer(
            middleware::from_fn_with_state(state.clone(),decode_coverage_headers)))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
                .expose_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            http_metrics,
            trace_slow_request,
        ));

    let app = if let Some(shadow) = shadow_api {
        app.layer(middleware::from_fn_with_state(shadow, shadow::fence))
    } else { app };
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!("listening on http://{}", cli.bind);
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

/// Array-valued raw read routes cannot add a JSON envelope without breaking
/// clients. Publish decoding completeness as headers on every DB-backed route.
async fn bounded_decode_summary(state: &AppState) -> Option<tn12_indexer_db::deferred_decode::DeferredDecodeSummary> {
    let writer = state.persister.as_ref()?;
    tokio::time::timeout(Duration::from_millis(250),
        tn12_indexer_db::deferred_decode::summary(writer.pool())).await.ok()?.ok()
}

async fn decode_coverage_headers(State(state): State<AppState>, request: axum::extract::Request, next: Next) -> Response {
    // Any deferred write between the two observations invalidates a clear label,
    // including an obligation inserted and resolved while the handler reads.
    let before = bounded_decode_summary(&state).await;
    let mut response = next.run(request).await;
    let after = bounded_decode_summary(&state).await;
    let status = match (before, after) {
        (Some(a), Some(b)) if a.pending == 0 && b.pending == 0 && a.generation == b.generation => "clear",
        (Some(a), Some(b)) if a.pending > 0 || b.pending > 0 => "pending",
        _ => "unknown",
    };
    response.headers_mut().insert("x-indexer-decoding-status", HeaderValue::from_static(status));
    // A currently clear response can become incomplete on the next accepted
    // transaction. Intermediaries must re-enter this fence on every read.
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status != "clear" {
        response.headers_mut().insert("x-indexer-coverage", HeaderValue::from_static("incomplete"));
    }
    response
}

/// Reject semantic reads that overlap partial canonical rollback, including a
/// complete recovery between the before/after observations. Diagnostics remain
/// available so operators can inspect and repair a fenced plan.
async fn recovery_read_fence(State(state): State<AppState>, request: axum::extract::Request, next: Next) -> Response {
    let path = request.uri().path();
    if path == "/health" || path.starts_with("/health/") || path == "/metrics" || path == "/readyz" || path == "/livez" || (state.persister.is_none() && state.history_pool.is_none()) {
        return next.run(request).await;
    }
    async fn observe(state: &AppState) -> Option<(i64, bool)> {
        let pool = state.persister.as_ref().map(|p| p.pool()).or(state.history_pool.as_ref())?;
        sync_queue::observe(pool).await
    }
    fn unavailable() -> Response {
        let mut response = (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "canonical_recovery_in_progress", "coverage": {"status": "incomplete"}
        }))).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        response.headers_mut().insert("x-indexer-coverage", HeaderValue::from_static("incomplete"));
        response
    }
    let Some((generation, false)) = observe(&state).await else { return unavailable(); };
    let mut response = next.run(request).await;
    if observe(&state).await != Some((generation, false)) { return unavailable(); }
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn trace_slow_request(
    State(metrics): State<Arc<HttpRequestMetrics>>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("<unmatched>")
        .to_string();
    // Process instance plus this server-generated sequence identifies the request.
    // Instrument the future, rather than holding a span guard across await, so
    // concurrent requests cannot inherit each other's route or request ID.
    let span = tracing::info_span!(
        "http_request",
        request_id = NEXT_HTTP_REQUEST_ID.fetch_add(1, Ordering::Relaxed),
        method = %method,
        route = route.as_str(),
    );
    async {
        let started = Instant::now();
        let mut response = next.run(request).await;
        if route == "/health" || route.starts_with("/health/") || route == "/metrics" {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, max-age=0"),
            );
        }
        let elapsed = started.elapsed();
        let elapsed_ms = elapsed.as_millis() as u64;
        let status = response.status();
        metrics.record(method.as_str(), &route, status, elapsed.as_secs_f64());

        if status.is_server_error() || elapsed_ms >= 2_000 {
            tracing::warn!(
                target: "http_request",
                method = %method,
                route,
                status = status.as_u16(),
                elapsed_ms,
                "slow or failed HTTP request"
            );
        } else if elapsed_ms >= 500 {
            tracing::info!(
                target: "http_request",
                method = %method,
                route,
                status = status.as_u16(),
                elapsed_ms,
                "slow HTTP request"
            );
        }

        response
    }
    .instrument(span)
    .await
}

async fn swagger_redirect() -> Redirect {
    Redirect::temporary("/swagger-ui/")
}

async fn payments_debug_ui() -> Html<&'static str> {
    Html(API_PAYMENT_DEBUG_UI_HTML)
}

const API_PAYMENT_DEBUG_UI_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>API Payment Debug</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f7f8fa;
      color: #15171c;
    }
    * { box-sizing: border-box; }
    body { margin: 0; }
    main { width: min(1040px, calc(100vw - 32px)); margin: 32px auto; }
    h1 { font-size: 24px; line-height: 1.2; margin: 0 0 8px; }
    p { margin: 0 0 18px; color: #5b6270; }
    .toolbar {
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      margin: 22px 0;
    }
    select, input, button {
      min-height: 42px;
      border: 1px solid #c8ced8;
      border-radius: 6px;
      background: #fff;
      color: #15171c;
      font: inherit;
    }
    select, input { width: 100%; padding: 0 12px; }
    button {
      padding: 0 18px;
      cursor: pointer;
      background: #1c6dd0;
      border-color: #1c6dd0;
      color: #fff;
      font-weight: 650;
    }
    button:disabled { opacity: .55; cursor: wait; }
    .status {
      min-height: 22px;
      margin-bottom: 10px;
      color: #5b6270;
      font-size: 14px;
    }
    pre {
      min-height: 360px;
      overflow: auto;
      margin: 0;
      padding: 16px;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      background: #10141c;
      color: #e8edf7;
      font-size: 13px;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media (max-width: 760px) {
      main { width: calc(100vw - 24px); margin: 20px auto; }
      .toolbar { grid-template-columns: 1fr; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
  <main id="payment-debug-app">
    <h1>API Payment Debug</h1>
    <p>Read-only lookup for redacted receipt, channel, settlement, and direct-payment proof status.</p>
    <form class="toolbar" id="lookup-form">
      <select id="lookup-kind" aria-label="Lookup type">
        <option value="receipt">Receipt id</option>
        <option value="channel">Channel id</option>
        <option value="settlement">Settlement or refund txid</option>
        <option value="direct">Direct proof txid</option>
      </select>
      <input id="lookup-id" autocomplete="off" spellcheck="false" placeholder="apr_..., apd_..., channel id, or txid" aria-label="Lookup id">
      <button id="lookup-button" type="submit">Lookup</button>
    </form>
    <div class="status" id="lookup-status">No lookup yet.</div>
    <pre id="lookup-output">{}</pre>
  </main>
  <script>
    const endpoints = {
      receipt: (id) => `/payments/receipts/${encodeURIComponent(id)}`,
      channel: (id) => `/payments/channels/${encodeURIComponent(id)}`,
      settlement: (id) => `/payments/settlements/${encodeURIComponent(id)}`,
      direct: (id) => `/payments/direct-proofs/${encodeURIComponent(id)}`
    };
    const labels = {
      receipt: "receipt",
      channel: "channel",
      settlement: "settlement/refund tx",
      direct: "direct proof"
    };
    const form = document.getElementById("lookup-form");
    const kind = document.getElementById("lookup-kind");
    const idInput = document.getElementById("lookup-id");
    const button = document.getElementById("lookup-button");
    const status = document.getElementById("lookup-status");
    const output = document.getElementById("lookup-output");

    kind.addEventListener("change", () => {
      const placeholders = {
        receipt: "apr_<credentialHashHex> or apd_<txidHex>",
        channel: "32-byte channel id hex",
        settlement: "32-byte settlement or refund txid hex",
        direct: "32-byte direct payment txid hex"
      };
      idInput.placeholder = placeholders[kind.value];
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const id = idInput.value.trim();
      if (!id) {
        status.textContent = "Enter an id first.";
        output.textContent = "{}";
        return;
      }
      const url = endpoints[kind.value](id);
      button.disabled = true;
      status.textContent = `Loading ${labels[kind.value]} from ${url}`;
      output.textContent = "{}";
      try {
        const response = await fetch(url, { headers: { "accept": "application/json" } });
        const text = await response.text();
        let body;
        try {
          body = JSON.parse(text);
          output.textContent = JSON.stringify(body, null, 2);
        } catch (_) {
          output.textContent = text || "{}";
        }
        status.textContent = `${response.status} ${response.statusText || ""}`.trim();
      } catch (error) {
        status.textContent = "Lookup failed";
        output.textContent = JSON.stringify({ error: String(error) }, null, 2);
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>"#;

async fn replay_fixture_dir(state: &AppState, dir: &std::path::Path) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();

    for path in &entries {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let tx: RestTransaction =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        {
            let mut holder = state.inner.write().await;
            holder.ingest(&tx)?;
        }
        if let Some(persister) = state.persister.as_ref() {
            let stats = persister.persist_tx(&tx).await?;
            tracing::info!(
                target: "fixture-replay",
                "ingested {} (db: blocks+{} covenants+{} utxos+{} spent+{} actions+{})",
                tx.transaction_id,
                stats.blocks_inserted, stats.covenants_inserted, stats.utxos_inserted,
                stats.utxos_spent, stats.actions_inserted,
            );
        } else {
            tracing::info!(target: "fixture-replay", "ingested {} (in-memory only)", tx.transaction_id);
        }
    }
    let holder = state.inner.read().await;
    tracing::info!(
        target: "fixture-replay",
        "replayed {} fixtures; emitted {} events",
        entries.len(),
        holder.events.len()
    );
    Ok(())
}

fn api_payments_enforced(cli: &Cli) -> bool {
    cli.api_payments_enabled && !cli.api_payments_rollback_free
}

fn redact_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
        let mut out = String::with_capacity(url.len());
        out.push_str(&url[..scheme_end]);
        out.push_str("***");
        out.push_str(&url[at..]);
        out
    } else {
        url.to_string()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryCoverage {
    status: &'static str,
    replay_status: &'static str,
    history_cursor_blue_score: Option<i64>,
    source_tip_blue_score: Option<i64>,
    replay_source_tip_blue_score: Option<i64>,
    live_tip_blue_score: Option<i64>,
    live_tip_age_ms: Option<i64>,
    chain_tip_blue_score: Option<i64>,
    gap_scores: Option<i64>,
    net_rate_scores_per_second: Option<f64>,
    eta_seconds: Option<i64>,
    cursor_age_ms: Option<i64>,
    historical_verification: Option<serde_json::Value>,
    verification_watermark_blue_score: Option<i64>,
    unverified_ranges: Option<Vec<recovery_health::UnverifiedRange>>,
    recovery: Option<recovery_health::RecoveryHealth>,
    settled_recheck: Option<settled_recheck::SettledRecheck>,
    deferred_decoding: Option<tn12_indexer_db::deferred_decode::DeferredDecodeSummary>,
    unverified_history: Option<tn12_indexer_db::persist::genesis::unverified::Summary>,
}

fn unknown_coverage() -> HistoryCoverage {
    HistoryCoverage {
        status: "unknown",
        replay_status: "unknown",
        history_cursor_blue_score: None,
        source_tip_blue_score: None,
        replay_source_tip_blue_score: None,
        live_tip_blue_score: None,
        live_tip_age_ms: None,
        chain_tip_blue_score: None,
        gap_scores: None,
        net_rate_scores_per_second: None,
        eta_seconds: None,
        cursor_age_ms: None,
        historical_verification: None,
        verification_watermark_blue_score: None,
        unverified_ranges: None,
        recovery: None,
        settled_recheck: None,
        deferred_decoding: None,
        unverified_history: None,
    }
}

fn coverage_for_unavailable_history() -> HistoryCoverage {
    let mut coverage = unknown_coverage();
    coverage.status = "incomplete";
    coverage
}

fn checkpoint_verifies_tip(checkpoint: Option<&serde_json::Value>, tip: Option<i64>) -> bool {
    let Some(checkpoint) = checkpoint else {
        return false;
    };
    let through = checkpoint
        .get("verifiedThroughBlueScore")
        .or_else(|| checkpoint.get("sourceCurrentAuditedThroughBlueScore"))
        .and_then(serde_json::Value::as_i64);
    checkpoint
        .get("verified")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && tip
            .zip(through)
            .is_some_and(|(tip, through)| tip >= 0 && through >= tip)
}

fn history_coverage_phase(
    verified: bool,
    cursor: Option<i64>,
    gap: Option<i64>,
    age_ms: Option<i64>,
) -> (&'static str, &'static str) {
    // A dated historical verification cannot certify a newly opened gap.
    if verified
        && cursor.is_some()
        && gap == Some(0)
        && age_ms.is_some_and(|age| (0..=120_000).contains(&age))
    {
        return ("complete", "verified");
    }
    let replay = if cursor.is_none() {
        "uninitialized"
    } else if gap.is_none() {
        "source_unavailable"
    } else if age_ms.is_some_and(|age| age > 120_000) {
        "stalled"
    } else if gap == Some(0) {
        "verifying"
    } else {
        "running"
    };
    ("incomplete", replay)
}

#[derive(Clone, Copy)]
struct HistoryProgressSample {
    cursor: i64,
    tip: i64,
    at: Instant,
    rate: Option<f64>,
}

fn measured_history_rate(
    sample: &mut Option<HistoryProgressSample>,
    cursor: i64,
    tip: i64,
    now: Instant,
) -> Option<f64> {
    match sample {
        Some(previous) if now.duration_since(previous.at) >= Duration::from_secs(60) => {
            let seconds = now.duration_since(previous.at).as_secs_f64();
            let rate = ((previous.tip - previous.cursor) - (tip - cursor)) as f64 / seconds;
            *sample = Some(HistoryProgressSample {
                cursor,
                tip,
                at: now,
                rate: Some(rate),
            });
            Some(rate)
        }
        Some(previous) => previous.rate,
        None => {
            *sample = Some(HistoryProgressSample {
                cursor,
                tip,
                at: now,
                rate: None,
            });
            None
        }
    }
}

async fn current_node_source_tip(state: &AppState) -> Option<i64> {
    state
        .source_observation
        .lock()
        .expect("source observation lock")
        .as_ref()?
        .fresh_score(&state.network_id, now_ms() as i64)
}

async fn history_coverage(state: &AppState) -> Result<HistoryCoverage> {
    let history_pool = state
        .history_pool
        .as_ref()
        .or_else(|| state.persister.as_ref().map(|persister| persister.pool()));
    let Some(history_pool) = history_pool else {
        return Ok(unknown_coverage());
    };
    let row = sqlx::query(
        "SELECT value, updated_at_ms FROM indexer_state WHERE key = 'chain_realtime_tip_cursor'",
    )
    .fetch_optional(history_pool)
    .await?;
    let (cursor, replay_source_tip, age_ms) = match row {
        Some(row) => {
            let value: serde_json::Value = row.get("value");
            let updated_at_ms: i64 = row.get("updated_at_ms");
            (
                value.get("blue_score").and_then(|value| value.as_i64()),
                value
                    .get("rest_database_blue_score")
                    .and_then(|value| value.as_i64()),
                Some((now_ms() as i64 - updated_at_ms).max(0)),
            )
        }
        None => (None, None, None),
    };
    let (live_tip, live_tip_age_ms) = if let Some(persister) = state.persister.as_ref() {
        let heartbeat = sqlx::query(
            "SELECT value, updated_at_ms FROM indexer_state WHERE key = 'chain_wrpc_acceptance_heartbeat'",
        )
        .fetch_optional(persister.pool())
        .await?;
        heartbeat
            .map(|row| {
                let value: serde_json::Value = row.get("value");
                (
                    value.get("blue_score").and_then(|value| value.as_i64()),
                    Some((now_ms() as i64 - row.get::<i64, _>("updated_at_ms")).max(0)),
                )
            })
            .unwrap_or((None, None))
    } else {
        (None, None)
    };
    let source_tip = current_node_source_tip(state).await;
    // Stale worker progress is diagnostic only, never a fresh chain head.
    let tip = source_tip;
    let historical_verification = if let Some(persister) = state.persister.as_ref() {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM indexer_state WHERE key = 'tn10_history_coverage_verified'",
        )
        .fetch_optional(persister.pool())
        .await?
    } else {
        None
    };
    let recovery_pool = state.persister.as_ref().map(|p| p.pool()).unwrap_or(history_pool);
    let recovery = recovery_health::read(recovery_pool, &state.network_id, now_ms() as i64).await?;
    let deferred_decoding=tn12_indexer_db::deferred_decode::summary(recovery_pool).await?;
    let unverified_history=tn12_indexer_db::persist::genesis::unverified::summary(history_pool).await?;
    let verified = unverified_history.pending_windows==0 && deferred_decoding.pending==0 && recovery.clear() && checkpoint_verifies_tip(historical_verification.as_ref(), tip);
    let gap = cursor.zip(tip).map(|(cursor, tip)| (tip - cursor).max(0));
    let (net_rate, eta) = if let (Some(cursor), Some(tip), Some(gap)) = (cursor, tip, gap) {
        let now = Instant::now();
        let mut sample = state
            .history_progress
            .lock()
            .expect("history progress lock");
        let rate = measured_history_rate(&mut sample, cursor, tip, now);
        let eta = rate
            .filter(|rate| *rate > 0.0)
            .map(|rate| (gap as f64 / rate) as i64);
        (rate, eta)
    } else {
        (None, None)
    };
    let settled_recheck = settled_recheck::read(history_pool, now_ms() as i64).await?;
    let stalled = settled_recheck.as_ref().is_some_and(|progress| progress.stalled());
    let reconciling = settled_recheck.as_ref().and_then(|p| p.reconciliation.as_ref())
        .is_some_and(|job| job.phase != "complete" || job.remaining_families > 0);
    let (status, mut replay_status) = history_coverage_phase(verified && !stalled && !reconciling, cursor, gap, age_ms);
    if reconciling && !stalled && gap.is_some_and(|gap| gap <= 200) {
        replay_status = "settled_recheck_reconciling";
    }
    if stalled && gap.is_some_and(|gap| gap <= 200) {
        replay_status = "settled_recheck_stalled";
    }
    if unverified_history.pending_windows>0 && !stalled && !reconciling {
        replay_status="unverified_source_windows";
    }
    let checkpoint=recovery_health::watermark(historical_verification.as_ref());
    let watermark=match (checkpoint,unverified_history.windows.first()) {
        (Some(value),Some(window))=>Some(value.min(window.window_start.saturating_sub(1))),
        _=>checkpoint,
    };
    let mut ranges=recovery_health::unverified(watermark,tip);
    for window in &unverified_history.windows {
        ranges.get_or_insert_with(Vec::new).push(recovery_health::UnverifiedRange {
            from_blue_score:window.window_start,
            through_blue_score:window.window_start+i64::from(window.width)-1,
            reason:"missing_source_transaction",
        });
    }
    Ok(HistoryCoverage {
        status,
        replay_status,
        history_cursor_blue_score: cursor,
        source_tip_blue_score: source_tip,
        replay_source_tip_blue_score: replay_source_tip,
        live_tip_blue_score: live_tip,
        live_tip_age_ms,
        chain_tip_blue_score: tip,
        gap_scores: gap,
        net_rate_scores_per_second: net_rate,
        eta_seconds: eta,
        cursor_age_ms: age_ms,
        verification_watermark_blue_score: watermark,
        unverified_ranges: ranges,
        recovery: Some(recovery),
        historical_verification,
        settled_recheck,
        deferred_decoding: Some(deferred_decoding),
        unverified_history: Some(unverified_history),
    })
}

async fn health_live(State(state): State<AppState>) -> Response {
    let Some(persister) = state.persister.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    match repo::scanner_health(persister.pool()).await {
        Ok(scanner) => {
            let tip = current_node_source_tip(&state).await;
            let recovery = match recovery_health::read(persister.pool(), &state.network_id, now_ms() as i64).await {
                Ok(value) => value,
                Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"reasons":["recovery_state_unavailable"],"error":error.to_string()}))).into_response(),
            };
            let direct_sync_queue=sync_queue::summary(persister.pool(),&state.network_id).await.ok();
            let scanner_ok = scanner_live_ingestion_healthy(&scanner, tip);
            let recovery_clear = recovery.clear();
            let ok = recovery_clear && scanner_ok;
            let mut reasons = Vec::new();
            if !recovery_clear { reasons.push("canonical_recovery_pending"); }
            if tip.is_none() {
                reasons.push("source_unavailable_or_stale");
            }
            if !scanner.live_acceptance_fresh {
                reasons.push("watcher_progress_stale");
            }
            if tip.is_some() && scanner.live_acceptance_fresh && !scanner_ok {
                reasons.push("live_ingestion_behind");
            }
            let source = state
                .source_observation
                .lock()
                .expect("source observation lock")
                .clone();
            (
                if ok {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                Json(json!({"ok": ok, "directSyncQueue": direct_sync_queue, "scanner": scanner, "source": source, "recovery": recovery, "restPublication": state.rest_publication.lock().expect("REST observation lock").clone(), "reasons": reasons})),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn health_history(State(state): State<AppState>) -> Response {
    match history_coverage(&state).await {
        Ok(coverage) => (StatusCode::OK, Json(json!({"coverage": coverage, "restPublication": state.rest_publication.lock().expect("REST observation lock").clone()}))).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn health(State(state): State<AppState>) -> Response {
    if let Some(p) = state.persister.as_ref() {
        match repo::health_snapshot(p.pool()).await {
            Ok(snapshot) => {
                let coverage = if state.history_pool.is_some() {
                    match history_coverage(&state).await {
                        Ok(coverage) => coverage,
                        Err(error) => {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"ok": false, "error": error.to_string()})),
                            )
                                .into_response();
                        }
                    }
                } else {
                    unknown_coverage()
                };
                let recovery_clear = recovery_health::read(p.pool(), &state.network_id, now_ms() as i64).await.is_ok_and(|r| r.clear());
                let healthy = recovery_clear && scanner_is_healthy(&snapshot.scanner)
                    && (state.history_pool.is_none() || coverage.status == "complete");
                let status = if healthy {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                return (
                    status,
                    Json(json!({
                        "ok": healthy,
                        "source": "postgres",
                        "covenants": snapshot.counts.covenants,
                        "activeUtxos": snapshot.counts.active_utxos,
                        "actions": snapshot.counts.actions,
                        "scanner": snapshot.scanner,
                        "coverage": coverage,
                        "classifications": snapshot.classifications,
                        "unknown": snapshot.unknown,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "source": "postgres",
                        "error": e.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }
    let holder = state.inner.read().await;
    Json(json!({
        "ok": true,
        "source": "memory",
        "events": holder.events.len(),
        "knownUtxos": holder.engine.known_count(),
    }))
    .into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    let mut output = String::new();
    output.push_str("# HELP tn10_indexer_ready Indexer API readiness state.\n");
    output.push_str("# TYPE tn10_indexer_ready gauge\n");
    output.push_str("# HELP tn10_indexer_health_ok Rich health snapshot state.\n");
    output.push_str("# TYPE tn10_indexer_health_ok gauge\n");
    output.push_str(
        "# HELP tn10_indexer_live_ok Live watcher health against the observed source tip.\n",
    );
    output.push_str("# TYPE tn10_indexer_live_ok gauge\n");
    output.push_str("# HELP tn10_indexer_history_gap_scores Historical REST gap in blue scores.\n");
    output.push_str("# TYPE tn10_indexer_history_gap_scores gauge\n");
    output.push_str(
        "# HELP tn10_indexer_history_net_rate_scores_per_second Measured net gap closure rate.\n",
    );
    output.push_str("# TYPE tn10_indexer_history_net_rate_scores_per_second gauge\n");
    output.push_str(
        "# HELP tn10_indexer_history_cursor_age_seconds Age of historical replay cursor.\n",
    );
    output.push_str("# TYPE tn10_indexer_history_cursor_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_settled_recheck_cursor_age_seconds Age of the last successfully completed settled replay window.\n# TYPE tn10_indexer_settled_recheck_cursor_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_settled_recheck_eligible Whether the next settled window is covered by history and mature at the source.\n# TYPE tn10_indexer_settled_recheck_eligible gauge\n");
    output.push_str("# HELP tn10_indexer_settled_recheck_next_blue_score Next pending settled replay window.\n# TYPE tn10_indexer_settled_recheck_next_blue_score gauge\n");
    output.push_str("# HELP tn10_indexer_settled_recheck_completed_windows_total Replay windows committed after scanning and normalization, including repeated sweeps; not unique coverage.\n# TYPE tn10_indexer_settled_recheck_completed_windows_total counter\n");
    output.push_str("# HELP tn10_indexer_settled_recheck_completed_scores_total Replay scores committed after scanning and normalization, including repeated sweeps; not unique coverage.\n# TYPE tn10_indexer_settled_recheck_completed_scores_total counter\n");
    output.push_str("# HELP tn10_indexer_db_cursor_lag_blocks Scanner cursor lag behind the observed REST database tip.\n");
    output.push_str("# TYPE tn10_indexer_db_cursor_lag_blocks gauge\n");
    output.push_str("# HELP tn10_indexer_rest_db_lag_blocks REST database lag behind the latest indexed live block.\n");
    output.push_str("# TYPE tn10_indexer_rest_db_lag_blocks gauge\n");
    output.push_str(
        "# HELP tn10_indexer_cursor_updated_age_seconds Age of the chain scan cursor update.\n",
    );
    output.push_str("# TYPE tn10_indexer_cursor_updated_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_rest_observation_fresh Whether the REST database tip observation is current.\n");
    output.push_str("# TYPE tn10_indexer_rest_observation_fresh gauge\n");
    output.push_str("# HELP tn10_indexer_live_acceptance_fresh Whether the wRPC watcher recently processed accepted transactions without missing bodies or write errors.\n");
    output.push_str("# TYPE tn10_indexer_live_acceptance_fresh gauge\n");
    output.push_str("# HELP tn10_indexer_live_acceptance_age_seconds Age of the latest complete wRPC acceptance observation.\n");
    output.push_str("# TYPE tn10_indexer_live_acceptance_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_latest_block_index_latency_seconds Time from the latest accepted covenant block timestamp to its database commit.\n");
    output.push_str("# TYPE tn10_indexer_latest_block_index_latency_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_latest_block_index_observed_age_seconds Age of the latest accepted covenant block commit observation.\n");
    output.push_str("# TYPE tn10_indexer_latest_block_index_observed_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_latest_action_age_seconds Age of the latest indexed covenant action.\n");
    output.push_str("# TYPE tn10_indexer_latest_action_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_activity_feed_age_seconds Age of the latest projected KCC20 activity feed row.\n");
    output.push_str("# TYPE tn10_indexer_activity_feed_age_seconds gauge\n");
    output.push_str("# HELP tn10_indexer_kcc20_projection_pending_age_seconds Age of the oldest unprojected KCC20 write, labeled by projection.\n");
    output.push_str("# TYPE tn10_indexer_kcc20_projection_pending_age_seconds gauge\n");

    let node = state
        .source_observation
        .lock()
        .expect("source observation lock")
        .clone();
    let node_tip = node
        .as_ref()
        .and_then(|sample| sample.fresh_score(&state.network_id, now_ms() as i64));
    let _ = writeln!(
        output,
        "tn10_indexer_node_observation_fresh {}",
        u8::from(node_tip.is_some())
    );
    if let Some(score) = node_tip {
        let _ = writeln!(output, "tn10_indexer_node_blue_score {score}");
    }
    if let Some(sample) = node {
        let age = (now_ms() as i64 - sample.observed_at_ms).max(0) as f64 / 1000.0;
        let _ = writeln!(output, "tn10_indexer_node_observation_age_seconds {age}");
    }
    let publication = state
        .rest_publication
        .lock()
        .expect("REST observation lock")
        .clone();
    let fresh = publication
        .as_ref()
        .is_some_and(|sample| (0..=15_000).contains(&(now_ms() as i64 - sample.observed_at_ms)));
    let _ = writeln!(
        output,
        "tn10_indexer_primary_rest_observation_fresh {}",
        u8::from(fresh)
    );
    if let Some(sample) = publication.as_ref().filter(|_| fresh) {
        let _ = writeln!(
            output,
            "tn10_indexer_primary_rest_block_blue_score {}",
            sample.database.blue_score
        );
        let _ = writeln!(
            output,
            "tn10_indexer_primary_rest_transaction_publication_current {}",
            u8::from(
                sample
                    .database
                    .require_current_transactions(now_ms() as i64)
                    .is_ok()
            )
        );
        if let Some(age) = sample.database.transaction_age_ms(now_ms() as i64) {
            let _ = writeln!(
                output,
                "tn10_indexer_primary_rest_transaction_publication_age_seconds {}",
                age as f64 / 1000.0
            );
        }
        if let Some(tip) = node_tip {
            let gap =
                tip.saturating_sub(i64::try_from(sample.database.blue_score).unwrap_or(i64::MAX));
            let _ = writeln!(
                output,
                "tn10_indexer_primary_rest_block_lag_scores {}",
                gap.max(0)
            );
        }
    }
    if let Some(p) = state.persister.as_ref() {
        sync_queue::write_metrics(p.pool(),&state.network_id,&mut output).await;
        if let Ok(history)=tn12_indexer_db::persist::genesis::unverified::summary(p.pool()).await {
            use std::fmt::Write as _;
            let _=writeln!(output,"tn10_indexer_unverified_history_windows {}",history.pending_windows);
            let _=writeln!(output,"tn10_indexer_unverified_history_retained_bytes {}",history.retained_bytes);
        }

        let ready = repo::ping(p.pool()).await.is_ok();
        let _ = writeln!(output, "tn10_indexer_ready {}", if ready { 1 } else { 0 });
        // The repair cursor can live in the primary database. Match the pool
        // fallback used by /health/history even without HISTORY_DATABASE_URL.
        let coverage = history_coverage(&state).await.ok();
        if let Some(coverage) = coverage.as_ref() {
            if let Some(decoding)=coverage.deferred_decoding.as_ref() {
                decoding.write_metrics(&mut output,now_ms() as i64);
            }
            if let Some(progress) = coverage.settled_recheck.as_ref() {
                progress.write_metrics(&mut output);
                let rest_tip = publication.as_ref()
                    .filter(|sample| fresh && sample.network.as_str() == state.network_id.as_str()
                        && sample.database.require_current_transactions(now_ms() as i64).is_ok())
                    .and_then(|sample| i64::try_from(sample.database.blue_score).ok());
                let eligible = coverage.history_cursor_blue_score.zip(rest_tip)
                    .is_some_and(|(history, source)| settled_recheck::eligible(progress.next_blue_score, history, source));
                let _ = writeln!(output, "tn10_indexer_settled_recheck_eligible {}", u8::from(eligible));
            }
            if let Some(recovery) = coverage.recovery.as_ref() {
                recovery.write_progress_metrics(&mut output, now_ms() as i64);
                let _ = writeln!(output, "tn10_indexer_recovery_pending_intents {}\ntn10_indexer_recovery_open_intervals {}\ntn10_indexer_recovery_pending_bytes {}\ntn10_indexer_recovery_clear {}",recovery.pending_intents,recovery.open_intervals,recovery.pending_bytes,if recovery.clear(){1}else{0});
                if let Some(age)=recovery.oldest_pending_intent_age_ms { let _ = writeln!(output,"tn10_indexer_recovery_oldest_intent_age_seconds {}",age as f64 / 1000.0); }
            }
            if let Some(watermark)=coverage.verification_watermark_blue_score { let _=writeln!(output,"tn10_indexer_history_verification_watermark_blue_score {watermark}"); }
            if let Some(gap) = coverage.gap_scores {
                let _ = writeln!(output, "tn10_indexer_history_gap_scores {gap}");
            }
            if let Some(rate) = coverage.net_rate_scores_per_second {
                let _ = writeln!(
                    output,
                    "tn10_indexer_history_net_rate_scores_per_second {rate}"
                );
            }
            if let Some(age_ms) = coverage.cursor_age_ms {
                let _ = writeln!(
                    output,
                    "tn10_indexer_history_cursor_age_seconds {}",
                    age_ms / 1000
                );
            }
        }

        match repo::health_snapshot(p.pool()).await {
            Ok(snapshot) => {
                let now = now_ms() as i64;
                let (recovery_clear, recovery_alert_healthy) = match coverage.as_ref().and_then(|c| c.recovery.as_ref()) {
                    Some(recovery) => (recovery.clear(), recovery.alert_healthy()),
                    None => recovery_health::read(p.pool(), &state.network_id, now)
                        .await
                        .map(|recovery| (recovery.clear(), recovery.alert_healthy()))
                        .unwrap_or((false, false)),
                };
                let scanner_live_ok = scanner_live_ingestion_healthy(
                    &snapshot.scanner,
                    current_node_source_tip(&state).await,
                );
                let live_ok = recovery_clear && scanner_live_ok;
                let live_operational_ok = recovery_alert_healthy && scanner_live_ok;
                let aggregate_scanner_ok = scanner_is_healthy(&snapshot.scanner);
                let _ = writeln!(
                    output,
                    "tn10_indexer_live_ok {}",
                    if live_ok { 1 } else { 0 }
                );
                let _ = writeln!(
                    output,
                    "tn10_indexer_live_operational_ok {}",
                    if live_operational_ok { 1 } else { 0 }
                );
                let _ = writeln!(
                    output,
                    "tn10_indexer_health_ok {}",
                    if recovery_clear && aggregate_scanner_ok
                        && (state.history_pool.is_none()
                            || coverage
                                .as_ref()
                                .is_some_and(|item| item.status == "complete"))
                    {
                        1
                    } else {
                        0
                    }
                );
                let _ = writeln!(
                    output,
                    "tn10_indexer_rest_observation_fresh {}",
                    if snapshot.scanner.rest_observation_fresh {
                        1
                    } else {
                        0
                    }
                );
                let _ = writeln!(
                    output,
                    "tn10_indexer_live_acceptance_fresh {}",
                    if snapshot.scanner.live_acceptance_fresh {
                        1
                    } else {
                        0
                    }
                );
                if let Some(age_ms) = snapshot.scanner.live_acceptance_age_ms {
                    let _ = writeln!(
                        output,
                        "tn10_indexer_live_acceptance_age_seconds {}",
                        age_ms / 1000
                    );
                }
                let _ = writeln!(
                    output,
                    "tn10_indexer_covenants {}",
                    snapshot.counts.covenants
                );
                let _ = writeln!(
                    output,
                    "tn10_indexer_active_utxos {}",
                    snapshot.counts.active_utxos
                );
                let _ = writeln!(output, "tn10_indexer_actions {}", snapshot.counts.actions);
                if let Some(lag) = snapshot.scanner.db_cursor_lag_blocks {
                    let _ = writeln!(output, "tn10_indexer_db_cursor_lag_blocks {lag}");
                }
                if let Some(lag) = snapshot.scanner.rest_db_lag_blocks {
                    let _ = writeln!(output, "tn10_indexer_rest_db_lag_blocks {lag}");
                }
                if let Some(updated_at_ms) = snapshot.scanner.cursor_updated_at_ms {
                    let age_seconds = (now - updated_at_ms).max(0) / 1000;
                    let _ = writeln!(
                        output,
                        "tn10_indexer_cursor_updated_age_seconds {age_seconds}"
                    );
                }
                if let Some(action_time_ms) = snapshot.scanner.latest_action_time_ms {
                    let age_seconds = (now - action_time_ms).max(0) / 1000;
                    let _ = writeln!(
                        output,
                        "tn10_indexer_latest_action_age_seconds {age_seconds}"
                    );
                }
                if let (Some(block_time_ms), Some(indexed_at_ms)) = (
                    snapshot.scanner.latest_block_time_ms,
                    snapshot.scanner.latest_block_indexed_at_ms,
                ) {
                    let latency_seconds =
                        indexed_at_ms.saturating_sub(block_time_ms).max(0) as f64 / 1000.0;
                    let _ = writeln!(
                        output,
                        "tn10_indexer_latest_block_index_latency_seconds {latency_seconds}"
                    );
                    let observed_age_seconds = (now - indexed_at_ms).max(0) / 1000;
                    let _ = writeln!(
                        output,
                        "tn10_indexer_latest_block_index_observed_age_seconds {observed_age_seconds}"
                    );
                }
            }
            Err(_) => {
                output.push_str("tn10_indexer_health_ok 0\n");
                output.push_str("tn10_indexer_live_ok 0\n");
            }
        }

        if let Ok(Some(activity_time_ms)) = repo::latest_activity_feed_time_ms(p.pool()).await {
            let age_seconds = (now_ms() as i64 - activity_time_ms).max(0) / 1000;
            let _ = writeln!(
                output,
                "tn10_indexer_activity_feed_age_seconds {age_seconds}"
            );
        }
        if let Ok(projections) = repo::kcc20_projection_freshness(p.pool()).await {
            for projection in [
                projections.market,
                projections.token_page,
                projections.activity_feed,
                projections.owner_orders,
                projections.owner_portfolio_assets,
            ] {
                let pending_age_seconds =
                    projection.pending_age_ms.unwrap_or(0).max(0) as f64 / 1000.0;
                let _ = writeln!(
                    output,
                    "tn10_indexer_kcc20_projection_pending_age_seconds{{projection=\"{}\"}} {pending_age_seconds}",
                    projection.name
                );
            }
        }
    } else {
        output.push_str("tn10_indexer_ready 1\n");
        output.push_str("tn10_indexer_health_ok 1\n");
    }
    output.push_str(&state.http_metrics.render());

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
        .into_response()
}

fn scanner_is_healthy(scanner: &repo::ScannerHealth) -> bool {
    scanner.rest_observation_fresh
        && scanner
            .rest_db_lag_blocks
            .is_none_or(|lag_blocks| lag_blocks <= repo::REST_DB_MAX_LAG_BLOCKS)
        && (scanner.live_acceptance_age_ms.is_none() || scanner.live_acceptance_fresh)
        && scanner
            .cursor_age_ms
            .is_some_and(|age_ms| age_ms <= SCANNER_HEALTH_MAX_CURSOR_AGE_MS)
        && scanner
            .db_cursor_lag_blocks
            .is_some_and(|lag_blocks| lag_blocks <= SCANNER_HEALTH_MAX_DB_CURSOR_LAG_BLOCKS)
}

fn scanner_live_ingestion_healthy(
    scanner: &repo::ScannerHealth,
    current_source_tip: Option<i64>,
) -> bool {
    // Accepted-transaction heartbeats can lag through a quiet transaction
    // interval. Canonical blocks persisted by the watcher or repair worker
    // also show chain progress; the fresh wRPC heartbeat is still required.
    let covered_score = scanner
        .live_acceptance_blue_score
        .into_iter()
        .chain(scanner.latest_block_blue_score)
        .chain(
            scanner
                .cursor_age_ms
                .filter(|age_ms| *age_ms <= SCANNER_HEALTH_MAX_CURSOR_AGE_MS)
                .and(scanner.cursor_blue_score),
        )
        .max();
    scanner.live_acceptance_fresh
        && current_source_tip
            .zip(covered_score)
            .is_some_and(|(source, live)| source.saturating_sub(live) <= LIVE_MAX_SOURCE_LAG_SCORES)
}

async fn explorer_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        let summary = repo::explorer_summary(p.pool()).await.map_err(internal)?;
        return Ok(Json(serde_json::to_value(summary).map_err(internal)?));
    }

    let holder = state.inner.read().await;
    Ok(Json(json!({
        "ok": true,
        "source": "memory",
        "counts": {
            "covenants": holder.snapshot().covenants.len(),
            "activeUtxos": holder.engine.known_count(),
            "actions": holder.events.len()
        },
        "scanner": null,
        "classifications": [],
        "unknown": { "total": 0, "unrevealed": 0, "unmatched": 0 },
        "templates": []
    })))
}

#[derive(Debug, Default, Deserialize)]
struct ExplorerSearchQuery {
    q: Option<String>,
    limit: Option<i64>,
}

async fn explorer_search(
    State(state): State<AppState>,
    Query(q): Query<ExplorerSearchQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let query = q.q.unwrap_or_default();
    let limit = bounded_i64(q.limit, 10, 50);
    if let Some(p) = state.persister.as_ref() {
        let aliases = wallet_identity_values(&query, &state.network_id);
        let results = repo::explorer_search_with_aliases(p.pool(), &query, &aliases, limit)
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::to_value(results).map_err(internal)?));
    }

    Ok(Json(json!([])))
}

async fn livez() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

async fn readyz(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        repo::ping(p.pool()).await.map_err(internal)?;
        return Ok(Json(json!({
            "ok": true,
            "source": "postgres",
        })));
    }
    Ok(Json(json!({
        "ok": true,
        "source": "memory",
    })))
}

async fn payments_pricing(
    State(state): State<AppState>,
) -> Json<api_payments::ApiPaymentPricingResponse> {
    Json(state.payment_policy.pricing_response())
}

async fn payments_metrics(State(state): State<AppState>) -> Json<ApiPaymentRuntimeMetricsSnapshot> {
    Json(state.payment_metrics.snapshot())
}

async fn payments_challenge(
    State(state): State<AppState>,
    Json(request): Json<api_payments::ApiPaymentChallengeRequest>,
) -> Response {
    match state
        .payment_policy
        .challenge_for_request(&request, now_ms())
    {
        Ok(challenge) => {
            let mut headers = HeaderMap::new();
            if let Ok(value) = api_payments::payment_challenge_header(&challenge.challenge) {
                headers.insert(api_payments::WWW_AUTHENTICATE, value);
            }
            (StatusCode::CREATED, headers, Json(challenge)).into_response()
        }
        Err(api_payments::ApiPaymentChallengeError::UnsupportedRoute) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "type": "https://kaspa.com/problems/payment-route-not-supported",
                "title": "Payment Route Not Supported",
                "status": 404
            })),
        )
            .into_response(),
        Err(api_payments::ApiPaymentChallengeError::RouteNotPriced) => (
            StatusCode::CONFLICT,
            Json(json!({
                "type": "https://kaspa.com/problems/payment-route-not-priced",
                "title": "Payment Route Not Priced",
                "status": 409
            })),
        )
            .into_response(),
        Err(api_payments::ApiPaymentChallengeError::DirectRecipientMissing) => (
            StatusCode::CONFLICT,
            Json(json!({
                "type": "https://kaspa.com/problems/payment-direct-recipient-missing",
                "title": "Direct Payment Recipient Missing",
                "status": 409
            })),
        )
            .into_response(),
        Err(api_payments::ApiPaymentChallengeError::InvalidBodyHash) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "type": "https://kaspa.com/problems/payment-invalid-request-binding",
                "title": "Invalid Payment Request Binding",
                "status": 400,
                "detail": "bodyHashHex must be 32-byte hex"
            })),
        )
            .into_response(),
    }
}

async fn payments_direct_proof(
    State(state): State<AppState>,
    Json(request): Json<api_payments::ApiDirectPaymentProofRequest>,
) -> Response {
    let amount_sompi = match state.payment_policy.validate_direct_payment_proof(&request) {
        Ok(amount_sompi) if amount_sompi <= i64::MAX as u64 => amount_sompi as i64,
        Ok(_) => {
            return direct_payment_problem(
                StatusCode::BAD_REQUEST,
                "payment-invalid-direct-proof",
                "Invalid Direct Payment Proof",
                Some("amountSompi is too large for storage"),
            )
        }
        Err(error) => {
            let status = match error {
                api_payments::ApiDirectPaymentProofError::RouteNotPriced
                | api_payments::ApiDirectPaymentProofError::DirectRecipientMissing => {
                    StatusCode::CONFLICT
                }
                _ => StatusCode::BAD_REQUEST,
            };
            return direct_payment_problem(
                status,
                "payment-invalid-direct-proof",
                "Invalid Direct Payment Proof",
                Some(error.to_string().as_str()),
            );
        }
    };

    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    let submitted = db_api_payments::submit_api_direct_payment_proof(
        persister.pool(),
        db_api_payments::NewApiDirectPaymentProof {
            challenge_id: request.challenge_id,
            network_id: request.network_id,
            txid_hex: request.txid_hex,
            payer_identifier: request.payer_identifier,
            recipient_address: request.recipient_address,
            amount_sompi,
            pricing_id: request.pricing_id,
            route: request.route,
            request_hash: request.request_hash,
            status: "submitted".to_string(),
            failure_reason: None,
            raw_status_snapshot: None,
            submitted_at_ms: now_ms() as i64,
            verified_at_ms: None,
            indexed_at_ms: None,
        },
    )
    .await;

    match submitted {
        Ok(Some(row)) => (StatusCode::ACCEPTED, Json(direct_payment_response(row))).into_response(),
        Ok(None) => direct_payment_problem(
            StatusCode::CONFLICT,
            "payment-direct-proof-replay",
            "Direct Payment Proof Replay",
            Some("txidHex or challengeId was already submitted"),
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-direct-proof-submit-failed",
            "Direct Payment Proof Submit Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn payments_direct_proof_status(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Response {
    if !is_hex_32(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-txid",
            "Invalid Direct Payment Txid",
            Some("txid must be 32-byte hex"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    match db_api_payments::api_direct_payment_proof_by_txid(persister.pool(), &txid).await {
        Ok(Some(row)) => (StatusCode::OK, Json(direct_payment_response(row))).into_response(),
        Ok(None) => direct_payment_problem(
            StatusCode::NOT_FOUND,
            "payment-direct-proof-not-found",
            "Direct Payment Proof Not Found",
            None,
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-direct-proof-read-failed",
            "Direct Payment Proof Read Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn payments_direct_proof_verify(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Response {
    if !is_hex_32(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-txid",
            "Invalid Direct Payment Txid",
            Some("txid must be 32-byte hex"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };
    let Some(rest) = state.direct_payment_rest.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-direct-verifier-unavailable",
            "Direct Payment Verifier Unavailable",
            Some("API_PAYMENT_REST_URL is not configured"),
        );
    };

    let proof =
        match db_api_payments::api_direct_payment_proof_by_txid(persister.pool(), &txid).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                return direct_payment_problem(
                    StatusCode::NOT_FOUND,
                    "payment-direct-proof-not-found",
                    "Direct Payment Proof Not Found",
                    None,
                )
            }
            Err(error) => {
                return direct_payment_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "payment-direct-proof-read-failed",
                    "Direct Payment Proof Read Failed",
                    Some(error.to_string().as_str()),
                )
            }
        };

    let tx = match rest.get_transaction(&txid).await {
        Ok(tx) => tx,
        Err(error) => {
            return direct_payment_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "payment-direct-tx-lookup-failed",
                "Direct Payment Tx Lookup Failed",
                Some(error.to_string().as_str()),
            )
        }
    };

    let verification = api_payments::verify_direct_payment_transaction(
        &api_payments::ApiDirectPaymentExpectation {
            challenge_id: proof.challenge_id.clone(),
            txid_hex: proof.txid_hex.clone(),
            recipient_address: proof.recipient_address.clone(),
            amount_sompi: proof.amount_sompi.max(0) as u64,
            request_hash: proof.request_hash.clone(),
        },
        &tx,
    );
    let verified_at_ms = now_ms() as i64;
    let indexed_at_ms = if verification.status == "accepted" {
        Some(verified_at_ms)
    } else {
        None
    };

    match db_api_payments::update_api_direct_payment_proof_status(
        persister.pool(),
        db_api_payments::ApiDirectPaymentProofStatusUpdate {
            txid_hex: proof.txid_hex,
            status: verification.status,
            failure_reason: verification.failure_reason,
            raw_status_snapshot: Some(verification.raw_status_snapshot),
            verified_at_ms,
            indexed_at_ms,
        },
    )
    .await
    {
        Ok(Some(row)) => (StatusCode::OK, Json(direct_payment_response(row))).into_response(),
        Ok(None) => direct_payment_problem(
            StatusCode::NOT_FOUND,
            "payment-direct-proof-not-found",
            "Direct Payment Proof Not Found",
            None,
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-direct-proof-update-failed",
            "Direct Payment Proof Update Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

fn direct_payment_response(
    row: db_api_payments::ApiDirectPaymentProofRow,
) -> api_payments::ApiDirectPaymentProofResponse {
    api_payments::ApiDirectPaymentProofResponse {
        receipt_id: direct_payment_receipt_id(&row.txid_hex),
        challenge_id: row.challenge_id,
        txid_hex: row.txid_hex,
        status: row.status,
        failure_reason: row.failure_reason,
        amount_sompi: row.amount_sompi.to_string(),
        pricing_id: row.pricing_id,
        route: row.route,
        request_hash: row.request_hash,
        verified_at_ms: row.verified_at_ms.map(|value| value.to_string()),
        indexed_at_ms: row.indexed_at_ms.map(|value| value.to_string()),
    }
}

async fn payments_receipt_status(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> Response {
    let direct_txid_hex = if is_channel_receipt_id(&receipt_id) {
        None
    } else if let Some(txid_hex) = direct_receipt_txid(&receipt_id) {
        Some(txid_hex.to_string())
    } else {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-receipt-id",
            "Invalid Payment Receipt Id",
            Some(
                "receiptId must be apr_ plus 32-byte credential hash hex or apd_ plus 32-byte txid hex",
            ),
        );
    };
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    if let Some(txid_hex) = direct_txid_hex {
        return match db_api_payments::api_direct_payment_proof_by_txid(persister.pool(), &txid_hex)
            .await
        {
            Ok(Some(row)) => (StatusCode::OK, Json(direct_payment_response(row))).into_response(),
            Ok(None) => direct_payment_problem(
                StatusCode::NOT_FOUND,
                "payment-receipt-not-found",
                "Payment Receipt Not Found",
                None,
            ),
            Err(error) => direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-receipt-read-failed",
                "Payment Receipt Read Failed",
                Some(error.to_string().as_str()),
            ),
        };
    }

    match db_api_payments::api_payment_receipt_by_id(persister.pool(), &receipt_id).await {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(api_payment_receipt_status_response(row)),
        )
            .into_response(),
        Ok(None) => direct_payment_problem(
            StatusCode::NOT_FOUND,
            "payment-receipt-not-found",
            "Payment Receipt Not Found",
            None,
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-receipt-read-failed",
            "Payment Receipt Read Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn payments_channel_status(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
) -> Response {
    if !is_hex_32(&channel_id) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-channel-id",
            "Invalid Payment Channel Id",
            Some("channelId must be 32-byte hex"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    let scanner = match repo::scanner_health(persister.pool()).await {
        Ok(scanner) => serde_json::to_value(scanner).unwrap_or_else(|_| json!(null)),
        Err(error) => {
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-channel-health-read-failed",
                "Payment Channel Health Read Failed",
                Some(error.to_string().as_str()),
            )
        }
    };

    match db_api_payments::api_payment_channel_status_by_id(persister.pool(), &channel_id).await {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(api_payment_channel_status_response(row, scanner)),
        )
            .into_response(),
        Ok(None) => direct_payment_problem(
            StatusCode::NOT_FOUND,
            "payment-channel-not-found",
            "Payment Channel Not Found",
            None,
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-channel-read-failed",
            "Payment Channel Read Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn payments_channel_sync(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<api_payments::ApiPaymentChannelSyncRequest>,
) -> Response {
    if !is_hex_32(&channel_id) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-channel-id",
            "Invalid Payment Channel Id",
            Some("channelId must be 32-byte hex"),
        );
    }
    let txid = request.txid_hex.trim().to_ascii_lowercase();
    if !is_hex_32(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-txid",
            "Invalid Payment Channel Sync Txid",
            Some("txidHex must be 32-byte hex"),
        );
    }
    if let Err(response) = state.channel_sync_guard.authorize(&headers) {
        return response;
    }
    if !state.channel_sync_guard.try_acquire(now_ms() as u64) {
        return direct_payment_problem(
            StatusCode::TOO_MANY_REQUESTS,
            "payment-channel-sync-rate-limited",
            "Payment Channel Sync Rate Limited",
            Some("too many channel sync requests; retry after the current minute window"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };
    let Some(rest) = state.direct_payment_rest.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-channel-sync-rest-unavailable",
            "Payment Channel Sync REST Unavailable",
            Some("configure KASPA_REST_URL or API_PAYMENT_REST_URL"),
        );
    };

    let tx = match rest.get_transaction(&txid).await {
        Ok(tx) => tx,
        Err(error) => {
            return direct_payment_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "payment-channel-sync-tx-lookup-failed",
                "Payment Channel Sync Tx Lookup Failed",
                Some(error.to_string().as_str()),
            )
        }
    };
    if !tx.transaction_id.eq_ignore_ascii_case(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_GATEWAY,
            "payment-channel-sync-txid-mismatch",
            "Payment Channel Sync Txid Mismatch",
            Some("REST returned a different transaction id than requested"),
        );
    }

    match async {
        let guarded=tn12_indexer_crawl::rest_replay_fence::for_transactions(persister,rest,std::slice::from_ref(&tx)).await?;
        guarded.persist_tx(&tx).await
    }.await {
        Ok(stats) => {
            tracing::info!(
                target: "api-payment-channel-sync",
                txid = %txid,
                channel_id = %channel_id,
                blocks_inserted = stats.blocks_inserted,
                covenants_inserted = stats.covenants_inserted,
                utxos_inserted = stats.utxos_inserted,
                utxos_spent = stats.utxos_spent,
                actions_inserted = stats.actions_inserted,
                "synced payment channel transaction"
            );
        }
        Err(error) => {
            if error.is::<tn12_indexer_db::persist::StaleRestAcceptance>() {
                return direct_payment_problem(StatusCode::SERVICE_UNAVAILABLE, "payment-channel-sync-source-changed",
                    "Payment Channel Sync Awaiting Canonical Source", Some("acceptance changed; retry after source reconciliation"));
            }
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-channel-sync-persist-failed",
                "Payment Channel Sync Persist Failed",
                Some(error.to_string().as_str()),
            )
        }
    }

    let scanner = match repo::scanner_health(persister.pool()).await {
        Ok(scanner) => serde_json::to_value(scanner).unwrap_or_else(|_| json!(null)),
        Err(error) => {
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-channel-health-read-failed",
                "Payment Channel Health Read Failed",
                Some(error.to_string().as_str()),
            )
        }
    };

    match db_api_payments::api_payment_channel_status_by_id(persister.pool(), &channel_id).await {
        Ok(Some(row)) => {
            let tx_matches = row.open_txid.as_deref() == Some(txid.as_str())
                || row.current_txid.as_deref() == Some(txid.as_str())
                || row.settlement_txid.as_deref() == Some(txid.as_str())
                || row.refund_txid.as_deref() == Some(txid.as_str());
            if !tx_matches {
                return direct_payment_problem(
                    StatusCode::CONFLICT,
                    "payment-channel-sync-tx-not-for-channel",
                    "Payment Channel Sync Tx Not For Channel",
                    Some("synced tx did not project onto the requested channel"),
                );
            }
            (
                StatusCode::OK,
                Json(api_payment_channel_status_response(row, scanner)),
            )
                .into_response()
        }
        Ok(None) => direct_payment_problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "payment-channel-sync-not-projected",
            "Payment Channel Sync Not Projected",
            Some("synced tx did not decode as an API payment channel lifecycle event"),
        ),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-channel-read-failed",
            "Payment Channel Read Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn tx_sync_actions(pool: &sqlx::PgPool, txid: &str) -> std::result::Result<Vec<repo::CovenantActionRow>, Response> {
    match repo::actions_by_txid_if_decoded(pool, txid).await {
        Ok(Some(actions)) => Ok(actions),
        Ok(None) => Err((StatusCode::ACCEPTED, Json(json!({"txidHex":txid,
            "indexed":false,"ingested":true,"decodingStatus":"pending",
            "coverage":{"status":"incomplete","reason":"unsupported_decoder_or_dependency"}}))).into_response()),
        Err(error) => Err(direct_payment_problem(StatusCode::SERVICE_UNAVAILABLE,
            "tx-sync-decoding-state-unavailable", "Transaction Decoding State Unavailable", Some(&error.to_string()))),
    }
}

async fn tx_sync(
    State(state): State<AppState>,
    Path(txid): Path<String>,
    Query(q): Query<TxSyncQuery>,
    headers: HeaderMap,
) -> Response {
    let txid = txid.trim().to_ascii_lowercase();
    if !is_hex_32(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "tx-sync-invalid-txid",
            "Invalid Transaction Sync Txid",
            Some("txid must be 32-byte hex"),
        );
    }
    if let Err(response) = state.channel_sync_guard.authorize(&headers) {
        return response;
    }
    if !state.channel_sync_guard.try_acquire(now_ms() as u64) {
        return direct_payment_problem(
            StatusCode::TOO_MANY_REQUESTS,
            "tx-sync-rate-limited",
            "Transaction Sync Rate Limited",
            Some("too many transaction sync requests; retry after the current minute window"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "tx-sync-persistence-unavailable",
            "Transaction Sync Persistence Unavailable",
            None,
        );
    };

    let Some((generation,false)) = sync_queue::observe(persister.pool()).await else {
        return enqueue_tx_sync(&state,&txid,q.force).await;
    };
    let response=tx_sync_now(&state,&txid,q.force,false).await;
    if sync_queue::observe(persister.pool()).await != Some((generation,false)) {
        return enqueue_tx_sync(&state,&txid,q.force).await;
    }
    let mut response=response;
    response.headers_mut().insert(header::CACHE_CONTROL,HeaderValue::from_static("no-store"));
    response
}

async fn enqueue_tx_sync(state: &AppState, txid: &str, force: bool) -> Response {
    let Some(writer)=state.persister.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match sync_queue::enqueue(writer.pool(),&state.network_id,txid,force).await {
        Ok(())=>{
            let mut response=(StatusCode::ACCEPTED,Json(json!({
                "txidHex":txid,"indexed":false,"ingested":false,"pending":true,"queued":true,
                "reason":"canonical_recovery_in_progress","retryAfterMs":2_000,
                "coverage":{"status":"incomplete"},"actionCount":0,"scanner":null,"actions":[],
                "persistStats":{"blocksInserted":0,"covenantsInserted":0,"utxosInserted":0,"utxosSpent":0,"actionsInserted":0}
            }))).into_response();
            response.headers_mut().insert(header::CACHE_CONTROL,HeaderValue::from_static("no-store"));
            response.headers_mut().insert(header::RETRY_AFTER,HeaderValue::from_static("2"));
            response.headers_mut().insert("x-indexer-coverage",HeaderValue::from_static("incomplete"));
            response
        }
        Err(error)=>direct_payment_problem(StatusCode::SERVICE_UNAVAILABLE,
            "tx-sync-queue-unavailable","Transaction Sync Queue Unavailable",Some(&error.to_string())),
    }
}

/// The caller owns authentication/queue receipt and checks the canonical fence.
/// Only the normal persister may apply transactions; queued work uses fresh REST.
async fn tx_sync_now(state: &AppState, txid: &str, force: bool, fresh: bool) -> Response {
    let Some(persister)=state.persister.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Queue completion requires fresh acceptance even if actions or a deferred
    // decode record already exist locally after an earlier attempt.
    if !fresh {
        let actions = match tx_sync_actions(persister.pool(), &txid).await {
            Ok(actions) => actions,
            Err(response) => return if response.status()==StatusCode::ACCEPTED { sync_queue::applied(response) } else {response},
        };
        if !force && !actions.is_empty() {
            return tx_sync_response(&txid, PersistStats::default(), json!(null), actions);
        }
    }

    let Some(rest) = state.direct_payment_rest.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "tx-sync-rest-unavailable",
            "Transaction Sync REST Unavailable",
            Some("configure KASPA_REST_URL or API_PAYMENT_REST_URL"),
        );
    };

    let lookup = if fresh {
        rest.get_transaction_with_explicit_acceptance(txid).await.map(Some)
    } else { rest.find_transaction(txid).await };
    let tx = match lookup {
        Ok(Some(tx)) => tx,
        Ok(None) => return tx_sync_pending_response(&txid),
        Err(error) => {
            return direct_payment_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "tx-sync-lookup-failed",
                "Transaction Sync Lookup Failed",
                Some(error.to_string().as_str()),
            )
        }
    };
    if !tx.transaction_id.eq_ignore_ascii_case(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_GATEWAY,
            "tx-sync-txid-mismatch",
            "Transaction Sync Txid Mismatch",
            Some("REST returned a different transaction id than requested"),
        );
    }

    if fresh && !tx.is_accepted {
        return tx_sync_pending_response(txid);
    }

    let stats = match async {
        let guarded=tn12_indexer_crawl::rest_replay_fence::for_transactions(persister,rest,std::slice::from_ref(&tx)).await?;
        guarded.persist_tx(&tx).await
    }.await {
        Ok(stats) => {
            tracing::info!(
                target: "tx-sync",
                txid = %txid,
                blocks_inserted = stats.blocks_inserted,
                covenants_inserted = stats.covenants_inserted,
                utxos_inserted = stats.utxos_inserted,
                utxos_spent = stats.utxos_spent,
                actions_inserted = stats.actions_inserted,
                "synced transaction"
            );
            stats
        }
        Err(error) => {
            if error.is::<tn12_indexer_db::persist::StaleRestAcceptance>() {
                return direct_payment_problem(StatusCode::SERVICE_UNAVAILABLE, "tx-sync-source-changed",
                    "Transaction Sync Awaiting Canonical Source", Some("acceptance changed; retry after source reconciliation"));
            }
            if is_transient_persist_error(&error) {
                return direct_payment_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "tx-sync-indexer-busy",
                    "Transaction Sync Indexer Busy",
                    Some("indexer persistence is under transient DB pressure; retry this tx sync shortly"),
                );
            }
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tx-sync-persist-failed",
                "Transaction Sync Persist Failed",
                Some(error.to_string().as_str()),
            );
        }
    };

    let actions = match tx_sync_actions(persister.pool(), &txid).await {
        Ok(actions) => actions,
        Err(response) => return if response.status()==StatusCode::ACCEPTED { sync_queue::applied(response) } else {response},
    };

    tx_sync_response(&txid, stats, json!(null), actions)
}

fn tx_sync_pending_response(txid: &str) -> Response {
    let mut response = (
        StatusCode::ACCEPTED,
        Json(json!({
            "txidHex": txid,
            "indexed": false,
            "pending": true,
            "reason": "transaction_not_found_yet",
            "retryAfterMs": 2_000,
            "actionCount": 0,
            "persistStats": {
                "blocksInserted": 0,
                "covenantsInserted": 0,
                "utxosInserted": 0,
                "utxosSpent": 0,
                "actionsInserted": 0,
            },
            "scanner": null,
            "actions": [],
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    response
}

fn tx_sync_response(
    txid: &str,
    stats: PersistStats,
    scanner: serde_json::Value,
    actions: Vec<repo::CovenantActionRow>,
) -> Response {
    sync_queue::applied((
        StatusCode::OK,
        Json(json!({
            "txidHex": txid,
            "indexed": !actions.is_empty(),
            "pending": false,
            "actionCount": actions.len(),
            "persistStats": {
                "blocksInserted": stats.blocks_inserted,
                "covenantsInserted": stats.covenants_inserted,
                "utxosInserted": stats.utxos_inserted,
                "utxosSpent": stats.utxos_spent,
                "actionsInserted": stats.actions_inserted,
            },
            "scanner": scanner,
            "actions": actions,
        })),
    )
        .into_response())
}

fn parse_list_env(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

async fn payments_channel_close(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    Json(request): Json<ApiPaymentChannelCloseRequest>,
) -> Response {
    if !is_hex_32(&channel_id) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-channel-id",
            "Invalid Payment Channel Id",
            Some("channelId must be 32-byte hex"),
        );
    }
    if request.channel_id != channel_id {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-close-channel-mismatch",
            "Payment Close Channel Mismatch",
            Some("request channelId must match path channelId"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    let now = now_ms() as u64;
    let channel =
        match db_api_payments::api_payment_channel_by_id(persister.pool(), &channel_id).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                return direct_payment_problem(
                    StatusCode::NOT_FOUND,
                    "payment-channel-not-found",
                    "Payment Channel Not Found",
                    None,
                )
            }
            Err(error) => {
                return direct_payment_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "payment-channel-read-failed",
                    "Payment Channel Read Failed",
                    Some(error.to_string().as_str()),
                )
            }
        };

    if let Err(error) = request.validate_static(ApiPaymentChannelCloseRequestExpectation {
        network_id: &channel.network_id,
        channel_id: &channel.channel_id,
        payer_pubkey: &channel.payer_pubkey,
        provider_pubkey: &channel.provider_pubkey,
        now_ms: now,
    }) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-close-request-invalid",
            "Payment Close Request Invalid",
            Some(error.to_string().as_str()),
        );
    }
    if let Err(error) = request.verify_payer_signature() {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-close-signature-invalid",
            "Payment Close Signature Invalid",
            Some(error.to_string().as_str()),
        );
    }

    let scanner = match repo::scanner_health(persister.pool()).await {
        Ok(scanner) => serde_json::to_value(scanner).unwrap_or_else(|_| json!(null)),
        Err(error) => {
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-channel-health-read-failed",
                "Payment Channel Health Read Failed",
                Some(error.to_string().as_str()),
            )
        }
    };

    let credential_hash_hex = request.signing_digest_hex();
    match db_api_payments::request_api_payment_channel_close(
        persister.pool(),
        db_api_payments::NewApiPaymentChannelCloseRequest {
            request,
            credential_hash_hex,
            status: "requested".to_string(),
            created_at_ms: now as i64,
        },
    )
    .await
    {
        Ok(Some(row)) => (
            StatusCode::ACCEPTED,
            Json(api_payment_channel_status_response(row, scanner)),
        )
            .into_response(),
        Ok(None) => {
            match db_api_payments::api_payment_channel_status_by_id(persister.pool(), &channel_id)
                .await
            {
                Ok(Some(row)) if row.status == "settlement_pending" || row.status == "settled" => (
                    StatusCode::OK,
                    Json(api_payment_channel_status_response(row, scanner)),
                )
                    .into_response(),
                Ok(Some(row)) if row.spent_sompi == 0 => direct_payment_problem(
                    StatusCode::CONFLICT,
                    "payment-channel-no-spend-to-close",
                    "Payment Channel Has No Spend To Close",
                    Some("provider settlement finalization requires accrued paid usage"),
                ),
                Ok(Some(row)) => direct_payment_problem(
                    StatusCode::CONFLICT,
                    "payment-channel-not-closeable",
                    "Payment Channel Not Closeable",
                    Some(format!("channel status is {}", row.status).as_str()),
                ),
                Ok(None) => direct_payment_problem(
                    StatusCode::NOT_FOUND,
                    "payment-channel-not-found",
                    "Payment Channel Not Found",
                    None,
                ),
                Err(error) => direct_payment_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "payment-channel-read-failed",
                    "Payment Channel Read Failed",
                    Some(error.to_string().as_str()),
                ),
            }
        }
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-channel-close-failed",
            "Payment Channel Close Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

async fn payments_settlement_status(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Response {
    if !is_hex_32(&txid) {
        return direct_payment_problem(
            StatusCode::BAD_REQUEST,
            "payment-invalid-txid",
            "Invalid Payment Settlement Txid",
            Some("txid must be 32-byte hex"),
        );
    }
    let Some(persister) = state.persister.as_ref() else {
        return direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        );
    };

    let scanner = match repo::scanner_health(persister.pool()).await {
        Ok(scanner) => serde_json::to_value(scanner).unwrap_or_else(|_| json!(null)),
        Err(error) => {
            return direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-settlement-health-read-failed",
                "Payment Settlement Health Read Failed",
                Some(error.to_string().as_str()),
            )
        }
    };

    match db_api_payments::api_payment_channel_tx_status_by_txid(persister.pool(), &txid).await {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(api_payment_settlement_status_response(
                txid,
                Some(row),
                scanner,
            )),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::OK,
            Json(api_payment_settlement_status_response(txid, None, scanner)),
        )
            .into_response(),
        Err(error) => direct_payment_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payment-settlement-read-failed",
            "Payment Settlement Read Failed",
            Some(error.to_string().as_str()),
        ),
    }
}

fn api_payment_channel_status_response(
    row: db_api_payments::ApiPaymentChannelStatusRow,
    scanner: serde_json::Value,
) -> api_payments::ApiPaymentChannelStatusResponse {
    let remaining = row.deposit_sompi.saturating_sub(row.spent_sompi);
    api_payments::ApiPaymentChannelStatusResponse {
        channel_id: row.channel_id,
        network_id: row.network_id,
        status: row.status,
        payer_identifier: row.payer_identifier,
        payer_pubkey: row.payer_pubkey,
        provider_pubkey: row.provider_pubkey,
        provider_payout_pubkey: row.provider_payout_pubkey,
        voucher_domain_hash: row.voucher_domain_hash,
        deposit_sompi: row.deposit_sompi.to_string(),
        reserve_sompi: row.reserve_sompi.to_string(),
        spent_sompi: row.spent_sompi.to_string(),
        remaining_sompi: remaining.to_string(),
        latest_sequence: row.latest_sequence.to_string(),
        max_spend_sompi: row.max_spend_sompi.map(|value| value.to_string()),
        refund_after_ms: row.refund_after_ms.map(|value| value.to_string()),
        close_after_ms: row.close_after_ms.to_string(),
        open_txid: row.open_txid,
        current_txid: row.current_txid,
        current_vout: row.current_vout,
        settlement_txid: row.settlement_txid,
        refund_txid: row.refund_txid,
        indexed_at_ms: row.indexed_at_ms.map(|value| value.to_string()),
        updated_at_ms: row.updated_at_ms.to_string(),
        scanner,
    }
}

fn api_payment_settlement_status_response(
    txid_hex: String,
    row: Option<db_api_payments::ApiPaymentChannelTxStatusRow>,
    scanner: serde_json::Value,
) -> api_payments::ApiPaymentSettlementStatusResponse {
    let Some(row) = row else {
        return api_payments::ApiPaymentSettlementStatusResponse {
            txid_hex,
            indexed: false,
            kind: None,
            channel_id: None,
            network_id: None,
            channel_status: None,
            settled_sequence: None,
            settled_total_sompi: None,
            provider_amount_sompi: None,
            payer_refund_sompi: None,
            indexer_status: None,
            created_at_ms: None,
            indexed_at_ms: None,
            updated_at_ms: None,
            scanner,
        };
    };
    api_payments::ApiPaymentSettlementStatusResponse {
        txid_hex: row.txid_hex,
        indexed: true,
        kind: Some(row.kind),
        channel_id: Some(row.channel_id),
        network_id: Some(row.network_id),
        channel_status: Some(row.channel_status),
        settled_sequence: row.settled_sequence.map(|value| value.to_string()),
        settled_total_sompi: row.settled_total_sompi.map(|value| value.to_string()),
        provider_amount_sompi: row.provider_amount_sompi.map(|value| value.to_string()),
        payer_refund_sompi: row.payer_refund_sompi.map(|value| value.to_string()),
        indexer_status: row.indexer_status,
        created_at_ms: row.created_at_ms.map(|value| value.to_string()),
        indexed_at_ms: row.indexed_at_ms.map(|value| value.to_string()),
        updated_at_ms: Some(row.updated_at_ms.to_string()),
        scanner,
    }
}

fn api_payment_receipt_status_response(
    row: db_api_payments::ApiPaymentReceiptRow,
) -> api_payments::ApiPaymentReceiptStatusResponse {
    api_payments::ApiPaymentReceiptStatusResponse {
        receipt_id: row.receipt_id,
        request_id: row.request_id,
        channel_id: row.channel_id,
        route: row.route,
        pricing_id: row.pricing_id,
        amount_sompi: row.amount_sompi.to_string(),
        voucher_sequence: row.voucher_sequence.map(|value| value.to_string()),
        response_status: row.response_status,
        duration_ms: row.duration_ms.map(|value| value.to_string()),
        created_at_ms: row.created_at_ms.to_string(),
        request_hash: row.voucher_request_hash,
        voucher_total_spent_sompi: row.voucher_total_spent_sompi.map(|value| value.to_string()),
        voucher_accepted_at_ms: row.voucher_accepted_at_ms.map(|value| value.to_string()),
        channel_status: row.channel_status,
        channel_spent_sompi: row.channel_spent_sompi.map(|value| value.to_string()),
        channel_latest_sequence: row.channel_latest_sequence.map(|value| value.to_string()),
    }
}

fn direct_payment_problem(
    status: StatusCode,
    code: &str,
    title: &str,
    detail: Option<&str>,
) -> Response {
    let mut body = json!({
        "type": format!("https://kaspa.com/problems/{code}"),
        "title": title,
        "status": status.as_u16(),
        "failureCode": code
    });
    if let Some(detail) = detail {
        body["detail"] = json!(detail);
    }
    (status, Json(body)).into_response()
}

fn is_hex_32(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

async fn snapshot(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if state.persister.is_some() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot is only available for fixture-backed in-memory runs".into(),
        ));
    }
    let holder = state.inner.read().await;
    Ok(Json(
        serde_json::to_value(holder.snapshot()).map_err(internal)?,
    ))
}

#[derive(Debug, Default, Deserialize)]
struct UtxosQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_active_utxos(
    State(state): State<AppState>,
    Query(q): Query<UtxosQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = bounded_i64(q.limit, 200, 1_000);
    let offset = q.offset.unwrap_or(0).max(0);
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::list_active_utxos(p.pool(), limit, offset)
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::to_value(rows).map_err(internal)?));
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "active UTXO lookup requires postgres state".into(),
    ))
}

async fn covenant_templates(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::covenant_template_summaries(p.pool())
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::to_value(rows).map_err(internal)?));
    }
    let holder = state.inner.read().await;
    let mut counts = BTreeMap::<String, i64>::new();
    for covenant in holder.snapshot().covenants {
        let name = covenant
            .template
            .map(str::to_string)
            .unwrap_or_else(|| "Unknown".to_string());
        *counts.entry(name).or_default() += 1;
    }
    let rows: Vec<_> = counts
        .into_iter()
        .map(|(template, covenant_count)| {
            json!({
                "template": template,
                "covenantCount": covenant_count
            })
        })
        .collect();
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

#[derive(Debug, Default, Deserialize)]
struct ListCovenantsQuery {
    /// Match against `template_name` (verified) OR `claimed_template`
    /// (wallet-declared) unless `verified_only` is set. Optional.
    template: Option<String>,
    /// Restrict the template filter to verified-on-chain templates only,
    /// hiding wallet claims that haven't been confirmed by a spend yet.
    #[serde(default)]
    verified_only: bool,
    /// Filter by row classification: covenant, inscription, or unknown.
    classification: Option<String>,
    /// Filter by reveal status: unrevealed, matched, or unmatched.
    #[serde(rename = "classificationStatus")]
    classification_status: Option<String>,
    /// Filter by a wallet-declared constructor arg name inside claimedArgs.args.
    #[serde(rename = "claimArg")]
    claim_arg: Option<String>,
    /// Optional value match for the arg selected by claimArg.
    #[serde(rename = "claimArgValue")]
    claim_arg_value: Option<String>,
    /// Wallet/address/pubkey value to match against common owner-like payload
    /// or decoded constructor args. Combines with template/q/active/sort.
    wallet: Option<String>,
    /// Optional arg name to narrow wallet matching, for example owner, seller,
    /// buyer, deployerAddress, ownerIdentifier, or stateOwner.
    #[serde(rename = "walletArg")]
    wallet_arg: Option<String>,
    /// Exact canonical covenant id or legacy script hash hex match.
    #[serde(rename = "covenantId")]
    covenant_id: Option<String>,
    /// Free-text search across covenant id / script hash / genesis txid /
    /// address / template / classification / claim source (case-insensitive).
    #[serde(rename = "q")]
    search: Option<String>,
    /// Activity filter: `true` = only covenants with active UTXOs, `false` =
    /// only fully-spent ones. Omitted = both.
    active: Option<bool>,
    /// Sort key: `recent` (default), `active`, `amount`, `template`.
    sort: Option<String>,
    /// Page size. Omitted = 50; values above 200 are capped.
    limit: Option<i64>,
    /// Row offset for paging. Omitted = 0.
    offset: Option<i64>,
}

const COVENANT_LIST_DEFAULT_LIMIT: i64 = 50;
const COVENANT_LIST_MAX_LIMIT: i64 = 200;

fn covenant_list_limit(value: Option<i64>) -> i64 {
    value
        .unwrap_or(COVENANT_LIST_DEFAULT_LIMIT)
        .clamp(0, COVENANT_LIST_MAX_LIMIT)
}

/// Builds an `X-Total-Count` header carrying the full match count (pre-paging)
/// so clients can render pagination without a second request.
fn total_count_header(total: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&total.to_string()) {
        headers.insert("x-total-count", value);
    }
    headers
}

fn prefix_for_network_id(network_id: &str) -> Prefix {
    if network_id.to_ascii_lowercase().contains("testnet") {
        Prefix::Testnet
    } else {
        Prefix::Mainnet
    }
}

fn wallet_identity_values(value: &str, network_id: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut values = BTreeSet::new();
    values.insert(trimmed.to_ascii_lowercase());

    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(trimmed) {
            if bytes.len() == 32 {
                // Wallet clients may query with an x-only pubkey while deploy payloads
                // store the equivalent Kaspa P2PK address. Match both forms.
                let address =
                    Address::new(prefix_for_network_id(network_id), Version::PubKey, &bytes)
                        .to_string();
                values.insert(address.to_ascii_lowercase());
            }
        }
    }

    if let Ok(address) = Address::try_from(trimmed) {
        if address.version == Version::PubKey && address.payload.len() == 32 {
            values.insert(hex::encode(address.payload.as_slice()));
        }
    }

    values.into_iter().collect()
}

async fn list_covenants(
    State(state): State<AppState>,
    Query(q): Query<ListCovenantsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let limit = covenant_list_limit(q.limit);
    let offset = q.offset.unwrap_or(0).max(0);
    if let Some(p) = state.persister.as_ref() {
        let wallet_aliases = q
            .wallet
            .as_deref()
            .map(|wallet| wallet_identity_values(wallet, &state.network_id))
            .unwrap_or_default();
        let search_aliases = q
            .search
            .as_deref()
            .map(|search| wallet_identity_values(search, &state.network_id))
            .unwrap_or_default();
        let (rows, total) = repo::list_covenant_summaries_paged_with_aliases(
            p.pool(),
            q.template.as_deref(),
            q.verified_only,
            q.classification.as_deref(),
            q.classification_status.as_deref(),
            q.claim_arg.as_deref(),
            q.claim_arg_value.as_deref(),
            q.wallet.as_deref(),
            &wallet_aliases,
            q.wallet_arg.as_deref(),
            q.covenant_id.as_deref(),
            q.search.as_deref(),
            &search_aliases,
            q.active,
            q.sort.as_deref(),
            Some(limit),
            Some(offset),
        )
        .await
        .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(serde_json::to_value(rows).map_err(internal)?),
        ));
    }
    // In-memory fallback (no Postgres): page the snapshot in process. Search,
    // sort and activity filters are Postgres-only; the snapshot path is dev-only.
    let holder = state.inner.read().await;
    let all = holder.snapshot().covenants;
    let total = all.len() as i64;
    let off = offset as usize;
    let paged: Vec<_> = all.into_iter().skip(off).take(limit as usize).collect();
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn covenant_detail(
    State(state): State<AppState>,
    Path(script_hash): Path<String>,
    Query(q): Query<CovenantRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let limit = bounded_i64(q.limit, 100, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let descending = q.sort.as_deref() == Some("desc");
    let entrypoints = comma_separated_values(q.entrypoint.as_deref())?;
    if let Some(p) = state.persister.as_ref() {
        let Some(summary) = repo::covenant_by_script_hash(p.pool(), &script_hash)
            .await
            .map_err(internal)?
        else {
            return Err((StatusCode::NOT_FOUND, format!("no covenant {script_hash}")));
        };
        let actions = repo::actions_for_covenant(
            p.pool(),
            &script_hash,
            limit,
            offset,
            descending,
            q.action.as_deref(),
            &entrypoints,
        )
        .await
        .map_err(internal)?;
        let total = repo::actions_for_covenant_count(
            p.pool(),
            &script_hash,
            q.action.as_deref(),
            &entrypoints,
        )
        .await
        .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(json!({
                "covenant": summary,
                "actions": actions,
                "actionsTotal": total,
                "actionsLimit": limit,
                "actionsOffset": offset,
            })),
        ));
    }
    let holder = state.inner.read().await;
    let snap = holder.snapshot();
    let Some(summary) = snap
        .covenants
        .iter()
        .find(|c| c.script_hash_hex == script_hash)
    else {
        return Err((StatusCode::NOT_FOUND, format!("no covenant {script_hash}")));
    };
    let mut related_events: Vec<&CovenantEvent> = snap
        .events
        .iter()
        .filter(|e| match &e.event {
            tn12_indexer_crawl::EventKind::Deploy {
                script_hash_hex, ..
            }
            | tn12_indexer_crawl::EventKind::Spend {
                script_hash_hex, ..
            }
            | tn12_indexer_crawl::EventKind::Continuation {
                script_hash_hex, ..
            } => script_hash_hex == &script_hash,
        })
        .collect();
    if descending {
        related_events.reverse();
    }
    let total = related_events.len() as i64;
    let related_events = related_events
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();
    Ok((
        total_count_header(total),
        Json(json!({
            "covenant": summary,
            "events": related_events,
            "actionsTotal": total,
            "actionsLimit": limit,
            "actionsOffset": offset,
        })),
    ))
}

async fn kcom_campaign(
    State(state): State<AppState>,
    Path(graph_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_hex_32(&graph_id) {
        return Err((StatusCode::BAD_REQUEST, "graph_id must be exact 32-byte hex".into()));
    }
    let persister = state.persister.as_ref().ok_or_else(||
        (StatusCode::SERVICE_UNAVAILABLE, "KCOM campaign reads require postgres state".into()))?;
    let campaign = repo::kcom_campaign(persister.pool(), &graph_id).await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "KCOM campaign projection is incomplete".into()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no KCOM campaign {graph_id}")))?;
    Ok(Json(serde_json::to_value(campaign).map_err(internal)?))
}

async fn kcom_participant(
    State(state): State<AppState>,
    Path((graph_id, authority)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_hex_32(&graph_id) || !is_hex_32(&authority) {
        return Err((StatusCode::BAD_REQUEST,
            "graph_id and authority must be exact 32-byte hex".into()));
    }
    let persister = state.persister.as_ref().ok_or_else(||
        (StatusCode::SERVICE_UNAVAILABLE, "KCOM participant reads require postgres state".into()))?;
    repo::kcom_campaign(persister.pool(), &graph_id).await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "KCOM campaign projection is incomplete".into()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no KCOM campaign {graph_id}")))?;
    let participant = repo::kcom_participant(persister.pool(), &graph_id, &authority).await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "KCOM participant projection is incomplete".into()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no KCOM participant {authority}")))?;
    Ok(Json(serde_json::to_value(participant).map_err(internal)?))
}

#[derive(Debug, Default, Deserialize)]
struct CovenantRowsQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    entrypoint: Option<String>,
}

fn comma_separated_values(value: Option<&str>) -> Result<Vec<String>, (StatusCode, String)> {
    let values = value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.len() > 16 || values.iter().any(|value| value.len() > 64) {
        return Err((
            StatusCode::BAD_REQUEST,
            "entrypoint accepts at most 16 comma-separated values of 64 characters each"
                .to_string(),
        ));
    }
    Ok(values)
}

async fn covenant_actions(
    State(state): State<AppState>,
    Path(script_hash): Path<String>,
    Query(q): Query<CovenantRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let limit = bounded_i64(q.limit, 100, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let descending = q.sort.as_deref() == Some("desc");
    let entrypoints = comma_separated_values(q.entrypoint.as_deref())?;
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::actions_for_covenant(
            p.pool(),
            &script_hash,
            limit,
            offset,
            descending,
            q.action.as_deref(),
            &entrypoints,
        )
        .await
        .map_err(internal)?;
        let total = repo::actions_for_covenant_count(
            p.pool(),
            &script_hash,
            q.action.as_deref(),
            &entrypoints,
        )
        .await
        .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(serde_json::to_value(rows).map_err(internal)?),
        ));
    }
    let holder = state.inner.read().await;
    let mut matched: Vec<CovenantEvent> = holder
        .snapshot()
        .events
        .into_iter()
        .filter(|e| match &e.event {
            tn12_indexer_crawl::EventKind::Deploy {
                script_hash_hex, ..
            }
            | tn12_indexer_crawl::EventKind::Spend {
                script_hash_hex, ..
            }
            | tn12_indexer_crawl::EventKind::Continuation {
                script_hash_hex, ..
            } => script_hash_hex == &script_hash,
        })
        .collect();
    if descending {
        matched.reverse();
    }
    let total = matched.len() as i64;
    let matched = matched
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(matched).map_err(internal)?),
    ))
}

async fn kcc20_snapshot_claims(
    State(state): State<AppState>,
    Path((controller_id, token_id)): Path<(String, String)>,
    Query(q): Query<CovenantRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    if !is_hex_32(&controller_id) || !is_hex_32(&token_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            "controller_id and token_id must be exact 32-byte hex".into(),
        ));
    }
    let Some(persister) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot claim history requires postgres state".into(),
        ));
    };
    let limit = bounded_i64(q.limit, 1_000, 1_000);
    let offset = q.offset.unwrap_or(0).max(0);
    let page =
        repo::snapshot_claim_actions(persister.pool(), &controller_id, &token_id, limit, offset)
            .await
            .map_err(internal)?;
    Ok((
        total_count_header(page.total),
        Json(serde_json::to_value(page).map_err(internal)?),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct CovenantUtxosQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default, alias = "ownerIdentifier")]
    owner_identifier: Option<String>,
    #[serde(default, alias = "stateMode")]
    state_mode: Option<i64>,
    #[serde(default, alias = "stateNull")]
    state_null: Option<bool>,
}

async fn covenant_utxos(
    State(state): State<AppState>,
    Path(script_hash): Path<String>,
    Query(q): Query<CovenantUtxosQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::covenant_active_utxos(
            p.pool(),
            &script_hash,
            bounded_i64(q.limit, 100, 200),
            q.offset.unwrap_or(0).max(0),
            q.address.as_deref(),
            q.owner_identifier.as_deref(),
            q.state_mode,
            q.state_null.unwrap_or(false),
        )
        .await
        .map_err(internal)?;
        let total = repo::covenant_active_utxos_count(
            p.pool(),
            &script_hash,
            q.address.as_deref(),
            q.owner_identifier.as_deref(),
            q.state_mode,
            q.state_null.unwrap_or(false),
        )
        .await
        .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(serde_json::to_value(rows).map_err(internal)?),
        ));
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "covenant UTXO lookup requires postgres state".into(),
    ))
}

async fn kcc20_fee_receipts(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if market_id.len() != 64 || !market_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "market ID must be 32-byte hex".into()));
    }
    let Some(persister) = state.persister.as_ref() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "fee receipt lookup requires postgres state".into()));
    };
    let page = repo::kcc20_fee_receipts_page(
        persister.pool(), &market_id.to_ascii_lowercase(),
        bounded_usize_as_i64(q.limit, 50, 100), usize_as_i64(q.offset.unwrap_or(0)),
    ).await.map_err(internal)?;
    Ok(Json(json!({
        "marketId": market_id.to_ascii_lowercase(),
        "receipts": page.receipts,
        "totalCount": page.total_count,
        "protocolClaimableSompi": page.protocol_claimable_sompi,
        "creatorClaimableSompi": page.creator_claimable_sompi,
        "coverage": {
            "status": "incomplete",
            "reason": "fee_receipt_history_not_yet_verified"
        }
    })))
}

async fn covenants_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let limit = bounded_usize_as_i64(q.limit, 100, 200);
    let offset = usize_as_i64(q.offset.unwrap_or(0));
    if let Some(p) = state.persister.as_ref() {
        let aliases = wallet_identity_values(&address, &state.network_id);
        let rows =
            repo::covenants_by_address_with_aliases(p.pool(), &address, &aliases, limit, offset)
                .await
                .map_err(internal)?;
        let total = repo::covenants_by_address_count(p.pool(), &address, &aliases)
            .await
            .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(serde_json::to_value(rows).map_err(internal)?),
        ));
    }
    let holder = state.inner.read().await;
    let matched: Vec<_> = holder
        .snapshot()
        .covenants
        .into_iter()
        .filter(|covenant| covenant.address == address)
        .collect();
    let total = matched.len() as i64;
    let paged = matched
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn utxos_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        let (rows, total) = repo::active_utxos_by_address_page(
            p.pool(),
            &address,
            bounded_usize_as_i64(q.limit, 100, 200),
            usize_as_i64(q.offset.unwrap_or(0)),
        )
        .await
        .map_err(internal)?;
        return Ok((
            total_count_header(total),
            Json(serde_json::to_value(rows).map_err(internal)?),
        ));
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "address UTXO lookup requires postgres state".into(),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct AddressEventsQuery {
    limit: Option<i64>,
}

async fn events_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<AddressEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = bounded_i64(q.limit, 200, 500);
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::actions_by_address(p.pool(), &address, limit)
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::to_value(rows).map_err(internal)?));
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "address event lookup requires postgres state".into(),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct FomoRoundsQuery {
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn fomo_rounds(
    State(state): State<AppState>,
    Query(q): Query<FomoRoundsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "FOMO rounds require postgres state".into(),
        ));
    };
    let rows = repo::fomo_rounds(
        p.pool(),
        q.active.unwrap_or(false),
        bounded_i64(q.limit, 100, 500),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    let total = repo::fomo_rounds_count(p.pool(), q.active.unwrap_or(false))
        .await
        .map_err(internal)?;
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

async fn fomo_round_detail(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    validate_hex_32(&covenant_id, "covenant_id")?;
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "FOMO round detail requires postgres state".into(),
        ));
    };
    let Some(round) = repo::fomo_round_by_id(p.pool(), &covenant_id)
        .await
        .map_err(internal)?
    else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no FOMO round {covenant_id}"),
        ));
    };
    let limit = bounded_usize_as_i64(q.limit, 100, 200);
    let offset = usize_as_i64(q.offset.unwrap_or(0));
    let actions = repo::actions_for_covenant(
        p.pool(),
        &round.covenant_id_hex,
        limit,
        offset,
        false,
        None,
        &[],
    )
    .await
    .map_err(internal)?;
    let actions_total =
        repo::actions_for_covenant_count(p.pool(), &round.covenant_id_hex, None, &[])
            .await
            .map_err(internal)?;
    let utxos = repo::covenant_active_utxos(
        p.pool(),
        &round.covenant_id_hex,
        limit,
        offset,
        None,
        None,
        None,
        false,
    )
    .await
    .map_err(internal)?;
    let utxos_total = repo::covenant_active_utxos_count(
        p.pool(),
        &round.covenant_id_hex,
        None,
        None,
        None,
        false,
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "round": round,
        "actions": actions,
        "actionsTotal": actions_total,
        "utxos": utxos,
        "utxosTotal": utxos_total,
        "limit": limit,
        "offset": offset,
    })))
}

async fn kcc20_holders(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 holders require postgres state".into(),
        ));
    };
    let limit = bounded_usize_as_i64(q.limit, 100, 200);
    let offset = usize_as_i64(q.offset.unwrap_or(0));
    let rows = repo::kcc20_holders(p.pool(), &covenant_id, limit, offset)
        .await
        .map_err(internal)?;
    let total = repo::kcc20_holders_count(p.pool(), &covenant_id)
        .await
        .map_err(internal)?;
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct WrapperSummaryQuery {
    #[serde(default)]
    include_pending: Option<bool>,
    #[serde(default, alias = "includePending")]
    include_pending_camel: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn kcc20_fee_markets_by_canonical(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 fee market discovery requires postgres state".into(),
        ));
    };
    validate_hex_32(&covenant_id, "covenant_id")?;
    let rows = repo::kcc20_fee_markets_by_canonical(p.pool(), &covenant_id)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_wrappers_by_canonical(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<WrapperSummaryQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 wrapper summaries require postgres state".into(),
        ));
    };
    validate_hex_32(&covenant_id, "covenant_id")?;
    let include_pending = q
        .include_pending
        .or(q.include_pending_camel)
        .unwrap_or(false);
    let rows = repo::kcc20_wrapper_summaries_by_canonical(
        p.pool(),
        &covenant_id,
        include_pending,
        bounded_i64(q.limit, 100, 200),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    let total =
        repo::kcc20_wrapper_summaries_by_canonical_count(p.pool(), &covenant_id, include_pending)
            .await
            .map_err(internal)?;
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

async fn kcc20_wrappers(
    State(state): State<AppState>,
    Query(q): Query<WrapperSummaryQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 wrapper summaries require postgres state".into(),
        ));
    };
    let include_pending = q
        .include_pending
        .or(q.include_pending_camel)
        .unwrap_or(false);
    let rows = repo::kcc20_wrapper_summaries(
        p.pool(),
        include_pending,
        bounded_i64(q.limit, 100, 200),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    let total = repo::kcc20_wrapper_summaries_count(p.pool(), include_pending)
        .await
        .map_err(internal)?;
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

async fn kcc20_token_summary(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 token summary requires postgres state".into(),
        ));
    };
    validate_hex_32(&covenant_id, "covenant_id")?;
    let Some(row) = repo::kcc20_token_summary(p.pool(), &covenant_id)
        .await
        .map_err(internal)?
    else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no KCC20 token summary {covenant_id}"),
        ));
    };
    Ok(Json(serde_json::to_value(row).map_err(internal)?))
}

async fn kcc20_utxos(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<CovenantUtxosQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 UTXOs require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_active_utxos(
        p.pool(),
        &covenant_id,
        bounded_i64(q.limit, 100, 200),
        q.offset.unwrap_or(0).max(0),
        q.address.as_deref(),
        q.owner_identifier.as_deref(),
        q.state_mode,
        q.state_null.unwrap_or(false),
    )
    .await
    .map_err(internal)?;
    let total = repo::covenant_active_utxos_count(
        p.pool(),
        &covenant_id,
        q.address.as_deref(),
        q.owner_identifier.as_deref(),
        q.state_mode,
        q.state_null.unwrap_or(false),
    )
    .await
    .map_err(internal)?;
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MarketRowsQuery {
    status: Option<String>,
    sort: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default, rename = "depthLimit")]
    depth_limit: Option<usize>,
}

fn bounded_market_rows_page(mut query: MarketRowsQuery) -> MarketRowsQuery {
    query.limit = Some(query.limit.unwrap_or(100).min(500));
    query
}

#[derive(Debug, Default, Deserialize)]
struct TradesQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
    #[serde(default)]
    side: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OwnerOrdersQuery {
    status: Option<String>,
    #[serde(rename = "tokenId")]
    token_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct OwnerActionsQuery {
    #[serde(rename = "tokenId")]
    token_id: Option<String>,
    action: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20PortfolioQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    include_wrapped: bool,
    #[serde(default)]
    include_reserves: bool,
    #[serde(default)]
    include_totals: bool,
    #[serde(default)]
    include_empty: bool,
    #[serde(default)]
    include_coverage: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20PortfolioAssetsQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    sort_by: Option<String>,
    #[serde(default)]
    sort_direction: Option<String>,
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    has_native_balance: Option<String>,
    #[serde(default)]
    has_orderbook_balance: Option<String>,
    #[serde(default)]
    has_open_orders: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20PortfolioAssetsResponse {
    items: Vec<repo::Kcc20PortfolioAssetRow>,
    total: i64,
    limit: i64,
    offset: i64,
    sort_by: String,
    sort_direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<HistoryCoverage>,
}

#[derive(Debug, Default, Deserialize)]
struct TxSyncQuery {
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Default, Deserialize)]
struct StatsQuery {
    #[serde(rename = "windowMs")]
    window_ms: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct MarketDiscoveryQuery {
    #[serde(rename = "tokenId")]
    token_id: Option<String>,
    #[serde(rename = "sortBy")]
    sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    sort_direction: Option<String>,
    #[serde(rename = "includeTotal")]
    include_total: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct MarketSnapshotsQuery {
    /// Comma-separated window list in milliseconds. Defaults to 24h and 7d.
    windows: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct CandlesQuery {
    #[serde(rename = "intervalMs")]
    interval_ms: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    /// Inclusive lower bound on the returned candles' `bucketTimeMs` (epoch
    /// ms). Bounded on the bucket boundary, not raw trade time -- a bucket is
    /// included or excluded whole, so this is safe to pass an unaligned
    /// wall-clock value (e.g. `Date.now() - 86_400_000`) without corrupting a
    /// boundary candle's OHLCV. Omit for the newest-N behavior that predates
    /// range support.
    #[serde(default)]
    from: Option<i64>,
    /// Exclusive upper bound on the returned candles' `bucketTimeMs` (epoch
    /// ms). Same bucket-boundary semantics as `from`.
    #[serde(default)]
    to: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct ActivityQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    side: Option<String>,
    #[serde(default)]
    entrypoint: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    txid: Option<String>,
    #[serde(default, rename = "orderId")]
    order_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct QuoteQuery {
    side: String,
    amount: String,
    #[serde(rename = "orderId")]
    order_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20DiscoveryResponse {
    items: Vec<repo::Kcc20MarketDiscoveryRow>,
    total: Option<i64>,
    limit: i64,
    offset: i64,
    sort_by: String,
    sort_direction: String,
    query_duration_ms: i64,
    freshness: repo::Kcc20MarketDiscoveryFreshness,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepthLevel {
    unit_price_sompi: String,
    token_amount: String,
    order_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20OrderbookResponse {
    token_id_hex: String,
    asks: Vec<repo::Kcc20ListingRow>,
    bids: Vec<repo::Kcc20BidRow>,
    ask_depth: Vec<DepthLevel>,
    bid_depth: Vec<DepthLevel>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20MarketRow {
    token_id_hex: String,
    best_ask_unit_price_sompi: Option<String>,
    best_bid_unit_price_sompi: Option<String>,
    spread_sompi: Option<String>,
    open_ask_count: usize,
    open_bid_count: usize,
    total_volume_sompi: String,
    total_trades: usize,
    last_trade_txid_hex: Option<String>,
    last_trade_time_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20StatsResponse {
    #[serde(flatten)]
    stats: repo::Kcc20TokenStatsRow,
    open_ask_depth_tokens: String,
    open_bid_depth_tokens: String,
    open_ask_depth_sompi: String,
    open_bid_depth_sompi: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20MarketSnapshotRow {
    token_id_hex: String,
    window_ms: i64,
    volume_sompi: String,
    token_volume: String,
    trade_count: i64,
    price_change_sompi: Option<String>,
    open_unit_price_sompi: Option<String>,
    high_unit_price_sompi: Option<String>,
    low_unit_price_sompi: Option<String>,
    close_unit_price_sompi: Option<String>,
    last_trade_txid_hex: Option<String>,
    last_trade_time_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kcc20QuoteResponse {
    token_id_hex: String,
    side: String,
    order_id: Option<String>,
    valid: bool,
    errors: Vec<String>,
    requested_amount: String,
    available_amount: Option<String>,
    min_fill_amount: Option<String>,
    unit_price_sompi: Option<String>,
    total_price_sompi: Option<String>,
    fee_ticket_id: Option<String>,
}

async fn kcc20_listings_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<MarketRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let q = bounded_market_rows_page(q);
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 listings require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_listings(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let (paged, total) = filter_listings_with_total(rows, &q);
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn kcc20_listings(
    State(state): State<AppState>,
    Query(q): Query<MarketRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let q = bounded_market_rows_page(q);
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 listings require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_listings(p.pool(), None, None)
        .await
        .map_err(internal)?;
    let (paged, total) = filter_listings_with_total(rows, &q);
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn kcc20_bids_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<MarketRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let q = bounded_market_rows_page(q);
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 bids require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_bids(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let (paged, total) = filter_bids_with_total(rows, &q);
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn kcc20_bids(
    State(state): State<AppState>,
    Query(q): Query<MarketRowsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let q = bounded_market_rows_page(q);
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 bids require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_bids(p.pool(), None, None)
        .await
        .map_err(internal)?;
    let (paged, total) = filter_bids_with_total(rows, &q);
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(paged).map_err(internal)?),
    ))
}

async fn kcc20_orderbook_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<MarketRowsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 orderbook requires postgres state".into(),
        ));
    };
    let mut query = q;
    if query.status.is_none() {
        query.status = Some("open".to_string());
    }
    let all_asks = repo::kcc20_listings(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let depth_asks = filter_listings_for_depth(all_asks.clone(), &query);
    let asks = filter_listings(all_asks, &query);
    let all_bids = repo::kcc20_bids(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let depth_bids = filter_bids_for_depth(all_bids.clone(), &query);
    let bids = filter_bids(all_bids, &query);
    let depth_limit = orderbook_depth_limit(&query);
    let response = Kcc20OrderbookResponse {
        token_id_hex: covenant_id,
        ask_depth: ask_depth(&depth_asks, depth_limit),
        bid_depth: bid_depth(&depth_bids, depth_limit),
        asks,
        bids,
    };
    Ok(Json(serde_json::to_value(response).map_err(internal)?))
}

async fn kcc20_stats_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 stats require postgres state".into(),
        ));
    };
    let window_ms = q.window_ms.unwrap_or(86_400_000).max(1);
    let stats = repo::kcc20_token_stats(p.pool(), &covenant_id, window_ms)
        .await
        .map_err(internal)?;
    let asks = filter_listings(
        repo::kcc20_listings(p.pool(), Some(&covenant_id), None)
            .await
            .map_err(internal)?,
        &MarketRowsQuery {
            status: Some("open".to_string()),
            ..Default::default()
        },
    );
    let bids = filter_bids(
        repo::kcc20_bids(p.pool(), Some(&covenant_id), None)
            .await
            .map_err(internal)?,
        &MarketRowsQuery {
            status: Some("open".to_string()),
            ..Default::default()
        },
    );
    let response = Kcc20StatsResponse {
        stats,
        open_ask_depth_tokens: sum_ask_tokens(&asks).to_string(),
        open_bid_depth_tokens: sum_bid_tokens(&bids).to_string(),
        open_ask_depth_sompi: sum_ask_value(&asks).to_string(),
        open_bid_depth_sompi: sum_bid_value(&bids).to_string(),
    };
    Ok(Json(serde_json::to_value(response).map_err(internal)?))
}

async fn kcc20_candles_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<CandlesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 candles require postgres state".into(),
        ));
    };
    let rows = repo::kcc20_candles(
        p.pool(),
        &covenant_id,
        q.interval_ms.unwrap_or(3_600_000).max(1),
        Some(q.limit.unwrap_or(500).clamp(1, 2_000)),
        q.from,
        q.to,
    )
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_activity_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 activity requires postgres state".into(),
        ));
    };
    let filters = repo::Kcc20ActivityFilter {
        kind: q.kind,
        scope: q.scope,
        side: q.side,
        entrypoint: q.entrypoint,
        owner: q.owner,
        txid: q.txid,
        order_id: q.order_id,
        from_ms: q.from,
        to_ms: q.to,
    };
    let rows = repo::kcc20_activity_filtered(
        p.pool(),
        &covenant_id,
        &filters,
        q.limit.unwrap_or(100).clamp(1, 1_000),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_quote_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<QuoteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 quote requires postgres state".into(),
        ));
    };
    let requested = parse_i128(Some(&q.amount)).unwrap_or(-1);
    let mut errors = Vec::new();
    if requested <= 0 {
        errors.push("amount must be a positive integer token amount".to_string());
    }
    let quote = match q.side.as_str() {
        "buy" => {
            let mut asks = filter_listings(
                repo::kcc20_listings(p.pool(), Some(&covenant_id), None)
                    .await
                    .map_err(internal)?,
                &MarketRowsQuery {
                    status: Some("open".to_string()),
                    sort: Some("price_asc".to_string()),
                    ..Default::default()
                },
            );
            if let Some(order_id) = q.order_id.as_deref() {
                asks.retain(|ask| ask.order_id == order_id);
            }
            build_quote(
                &covenant_id,
                "buy",
                requested,
                q.order_id,
                asks.first(),
                None,
                errors,
            )
        }
        "sell" => {
            let mut bids = filter_bids(
                repo::kcc20_bids(p.pool(), Some(&covenant_id), None)
                    .await
                    .map_err(internal)?,
                &MarketRowsQuery {
                    status: Some("open".to_string()),
                    sort: Some("price_desc".to_string()),
                    ..Default::default()
                },
            );
            if let Some(order_id) = q.order_id.as_deref() {
                bids.retain(|bid| bid.order_id == order_id);
            }
            build_quote(
                &covenant_id,
                "sell",
                requested,
                q.order_id,
                None,
                bids.first(),
                errors,
            )
        }
        _ => {
            errors.push("side must be buy or sell".to_string());
            Kcc20QuoteResponse {
                token_id_hex: covenant_id,
                side: q.side,
                order_id: q.order_id,
                valid: false,
                errors,
                requested_amount: q.amount,
                available_amount: None,
                min_fill_amount: None,
                unit_price_sompi: None,
                total_price_sompi: None,
                fee_ticket_id: None,
            }
        }
    };
    Ok(Json(serde_json::to_value(quote).map_err(internal)?))
}

async fn kcc20_trades_for_token(
    State(state): State<AppState>,
    Path(covenant_id): Path<String>,
    Query(q): Query<TradesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 trades require postgres state".into(),
        ));
    };
    validate_owner_query(q.address.as_deref())?;
    validate_trade_side(q.side.as_deref())?;
    let rows = repo::kcc20_trades(
        p.pool(),
        Some(&covenant_id),
        q.address.as_deref(),
        q.side.as_deref(),
        q.from,
        q.to,
        bounded_i64(q.limit, 200, 1_000),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_order_detail_for_token(
    State(state): State<AppState>,
    Path((covenant_id, order_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 order detail requires postgres state".into(),
        ));
    };
    let asks = repo::kcc20_listings(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let bids = repo::kcc20_bids(p.pool(), Some(&covenant_id), None)
        .await
        .map_err(internal)?;
    let ask = asks.iter().find(|row| row.order_id == order_id);
    let bid = bids.iter().find(|row| row.order_id == order_id);
    let lineage = build_orderbook_order_lineage(p.as_ref(), &covenant_id, &order_id).await?;
    if ask.is_none() && bid.is_none() && lineage.is_empty() {
        return Err((StatusCode::NOT_FOUND, "order not found".into()));
    }
    let fills: Vec<_> = lineage
        .iter()
        .filter_map(|item| {
            item.get("orderId")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect();
    let fill_order_ids: BTreeSet<_> = fills.into_iter().collect();
    let fills: Vec<_> = repo::kcc20_activity(p.pool(), &covenant_id, 1_000, 0)
        .await
        .map_err(internal)?
        .into_iter()
        .filter(|row| {
            row.kind == "trade"
                && row
                    .order_id
                    .as_ref()
                    .is_some_and(|order_id| fill_order_ids.contains(order_id))
        })
        .collect();
    let current = if let Some(ask) = ask {
        serde_json::to_value(ask).map_err(internal)?
    } else if let Some(bid) = bid {
        serde_json::to_value(bid).map_err(internal)?
    } else {
        serde_json::Value::Null
    };
    Ok(Json(json!({
        "tokenIdHex": covenant_id,
        "orderId": order_id,
        "side": if ask.is_some() { "ask" } else if bid.is_some() { "bid" } else { "historical" },
        "status": ask.map(|row| row.status.as_str()).or_else(|| bid.map(|row| row.status.as_str())).unwrap_or("historical"),
        "current": current,
        "ask": ask,
        "bid": bid,
        "lineage": lineage,
        "fills": fills,
    })))
}

async fn kcc20_trades_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<TradesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 trades require postgres state".into(),
        ));
    };
    validate_owner_query(Some(&address))?;
    validate_trade_side(q.side.as_deref())?;
    let rows = repo::kcc20_trades(
        p.pool(),
        None,
        Some(&address),
        q.side.as_deref(),
        q.from,
        q.to,
        bounded_i64(q.limit, 200, 1_000),
        q.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_orders_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<OwnerOrdersQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 address orders require postgres state".into(),
        ));
    };
    validate_owner_query(Some(&address))?;

    let rows = repo::kcc20_owner_orders(
        p.pool(),
        &address,
        q.token_id.as_deref(),
        q.status.as_deref(),
        bounded_i64(q.limit.map(|v| v as i64), 200, 1_000),
        q.offset.unwrap_or(0).max(0) as i64,
        q.from,
        q.to,
    )
    .await
    .map_err(internal)?;
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_actions_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<OwnerActionsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 address actions require postgres state".into(),
        ));
    };
    let lookup = kcc20_owner_lookup(&address)?;
    if let Some(token_id) = q.token_id.as_deref() {
        validate_hex_32(token_id, "tokenId")?;
    }
    let owner_or_address = match &lookup {
        Kcc20OwnerLookup::OwnerIdentifierHex(owner) => owner.as_str(),
        Kcc20OwnerLookup::CovenantAddress(address) => address.as_str(),
    };
    let history_enabled = std::env::var("KCC20_OWNER_ACTION_HISTORY_ENABLED")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let history_rows = if history_enabled {
        match repo::kcc20_actions_for_owner_materialized_if_ready(
            p.pool(),
            owner_or_address,
            q.token_id.as_deref(),
            q.action.as_deref(),
            bounded_i64(q.limit, 200, 1_000),
            q.offset.unwrap_or(0).max(0),
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(error = %error, "owner-action history unavailable; using source query");
                None
            }
        }
    } else {
        None
    };
    let rows = if let Some(rows) = history_rows {
        rows
    } else {
        repo::kcc20_actions_for_owner(
            p.pool(),
            owner_or_address,
            q.token_id.as_deref(),
            q.action.as_deref(),
            bounded_i64(q.limit, 200, 1_000),
            q.offset.unwrap_or(0).max(0),
        )
        .await
        .map_err(internal)?
    };
    Ok(Json(serde_json::to_value(rows).map_err(internal)?))
}

async fn kcc20_balances_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 address balances require postgres state".into(),
        ));
    };
    validate_owner_query(Some(&address))?;
    let rows = repo::kcc20_balances_for_owner_paged(
        p.pool(),
        &address,
        bounded_usize_as_i64(q.limit, 200, 1_000),
        usize_as_i64(q.offset.unwrap_or(0)),
    )
    .await
    .map_err(internal)?;
    let total = repo::kcc20_balances_for_owner_count(p.pool(), &address)
        .await
        .map_err(internal)?;
    let coverage = history_coverage(&state)
        .await
        .unwrap_or_else(|_| coverage_for_unavailable_history());
    let mut headers = total_count_header(total);
    headers.insert(
        "x-tn10-coverage-status",
        HeaderValue::from_static(coverage.status),
    );
    let body = if q.include_coverage {
        json!({"items": rows, "coverage": coverage})
    } else {
        serde_json::to_value(rows).map_err(internal)?
    };
    Ok((headers, Json(body)))
}

async fn kcc20_portfolio_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<Kcc20PortfolioQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 address portfolio requires postgres state".into(),
        ));
    };
    let owner_hex = kcc20_owner_identifier_lookup(&address, "portfolio")?;
    let options = repo::Kcc20PortfolioOptions {
        include_wrapped: q.include_wrapped,
        include_reserves: q.include_reserves,
        include_totals: q.include_totals,
        include_empty: q.include_empty,
        limit: bounded_i64(q.limit, 200, 1_000),
        offset: q.offset.unwrap_or(0).max(0),
    };
    let (rows, total) = repo::kcc20_portfolio_for_owner(p.pool(), &owner_hex, options)
        .await
        .map_err(internal)?;
    let coverage = history_coverage(&state)
        .await
        .unwrap_or_else(|_| coverage_for_unavailable_history());
    let mut headers = total_count_header(total);
    headers.insert(
        "x-tn10-coverage-status",
        HeaderValue::from_static(coverage.status),
    );
    let body = if q.include_coverage {
        json!({"items": rows, "coverage": coverage})
    } else {
        serde_json::to_value(rows).map_err(internal)?
    };
    Ok((headers, Json(body)))
}

async fn kcc20_portfolio_assets_for_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<Kcc20PortfolioAssetsQuery>,
) -> Result<Json<Kcc20PortfolioAssetsResponse>, (StatusCode, String)> {
    let owner_hex = kcc20_owner_identifier_lookup(&address, "portfolio assets")?;
    if let Some(token_id) = q.token_id.as_deref() {
        validate_hex_32(token_id, "tokenId")?;
    }
    validate_portfolio_asset_search(q.search.as_deref())?;

    let sort_by = normalize_portfolio_asset_sort_by(q.sort_by.as_deref())
        .ok_or((StatusCode::BAD_REQUEST, "unsupported sortBy".into()))?
        .to_string();
    let sort_direction = normalize_portfolio_asset_sort_direction(q.sort_direction.as_deref())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "sortDirection must be asc or desc".into(),
        ))?
        .to_string();
    let has_native_balance =
        portfolio_asset_query_bool("hasNativeBalance", q.has_native_balance.as_deref())?;
    let has_orderbook_balance =
        portfolio_asset_query_bool("hasOrderbookBalance", q.has_orderbook_balance.as_deref())?;
    let has_open_orders =
        portfolio_asset_query_bool("hasOpenOrders", q.has_open_orders.as_deref())?;
    let (limit, offset) = portfolio_asset_page_bounds(q.limit, q.offset)?;
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 portfolio assets require postgres state".into(),
        ));
    };
    if !repo::kcc20_owner_portfolio_assets_initialized(p.pool())
        .await
        .map_err(internal)?
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 portfolio assets are not initialized; wait for the projector".into(),
        ));
    }
    let page = repo::kcc20_portfolio_assets_for_owner(
        p.pool(),
        &owner_hex,
        repo::Kcc20PortfolioAssetOptions {
            token_id_hex: q.token_id.map(|value| value.to_ascii_lowercase()),
            search: q.search,
            has_native_balance,
            has_orderbook_balance,
            has_open_orders,
            sort_by: sort_by.clone(),
            sort_direction: sort_direction.clone(),
            limit,
            offset,
        },
    )
    .await
    .map_err(internal)?;

    Ok(Json(Kcc20PortfolioAssetsResponse {
        items: page.items,
        total: page.total,
        limit,
        offset,
        sort_by,
        sort_direction,
        coverage: if state.history_pool.is_some() {
            Some(
                history_coverage(&state)
                    .await
                    .unwrap_or_else(|_| coverage_for_unavailable_history()),
            )
        } else {
            None
        },
    }))
}

async fn kcc20_markets(
    State(state): State<AppState>,
    Query(q): Query<PaginationQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 markets require postgres state".into(),
        ));
    };
    let limit = bounded_i64(
        q.limit
            .map(|limit| i64::try_from(limit).unwrap_or(i64::MAX)),
        500,
        1_000,
    );
    let offset = q
        .offset
        .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let page =
        repo::kcc20_market_discovery(p.pool(), None, "tokenId", "asc", limit, offset.max(0), true)
            .await
            .map_err(internal)?;
    let total = page.total.unwrap_or(page.items.len() as i64).max(0);
    let rows = page
        .items
        .into_iter()
        .map(|market| Kcc20MarketRow {
            token_id_hex: market.token_id_hex,
            best_ask_unit_price_sompi: market.best_ask_unit_price_sompi,
            best_bid_unit_price_sompi: market.best_bid_unit_price_sompi,
            spread_sompi: market.spread_sompi,
            open_ask_count: market.open_ask_count.max(0) as usize,
            open_bid_count: market.open_bid_count.max(0) as usize,
            total_volume_sompi: market.total_volume_sompi,
            total_trades: market.total_trades.max(0) as usize,
            last_trade_txid_hex: market.last_trade_txid_hex,
            last_trade_time_ms: market.last_trade_time_ms,
        })
        .collect::<Vec<_>>();
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

async fn kcc20_discovery(
    State(state): State<AppState>,
    Query(q): Query<MarketDiscoveryQuery>,
) -> Response {
    match kcc20_discovery_response(&state, q).await {
        Ok(body) => (HeaderMap::new(), Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn payment_proof_kcc20_discovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<MarketDiscoveryQuery>,
) -> Response {
    let started_at_ms = now_ms();
    let payment = match authorize_route_payment(
        &state,
        &headers,
        state.payment_policy.route_policy(
            api_payments::API_PAYMENT_PROOF_DISCOVERY_ROUTE,
            api_payments::get_request_hash(&uri),
            now_ms(),
        ),
    )
    .await
    {
        Ok(payment) => payment,
        Err(response) => return response,
    };

    let body = match kcc20_discovery_response(&state, q).await {
        Ok(body) => body,
        Err(err) => return err.into_response(),
    };
    let mut response_headers = HeaderMap::new();
    if let Some((receipt, policy)) = payment.as_ref() {
        if let Err(response) = record_api_payment_response(
            &state,
            &mut response_headers,
            receipt,
            policy,
            started_at_ms,
        )
        .await
        {
            return response;
        }
    }
    (response_headers, Json(body)).into_response()
}

async fn payment_proof_body_echo(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let started_at_ms = now_ms();
    let body_hash_hex = hex::encode(blake2b_256(&body));
    let request_hash =
        api_payments::get_request_hash_for_method("POST", uri.path(), uri.query(), &body_hash_hex);
    let payment = match authorize_route_payment(
        &state,
        &headers,
        state.payment_policy.route_policy(
            api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
            request_hash,
            now_ms(),
        ),
    )
    .await
    {
        Ok(payment) => payment,
        Err(response) => return response,
    };

    let response_body = json!({
        "ok": true,
        "route": api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
        "bodyHashHex": body_hash_hex,
        "bodyByteLength": body.len(),
    });
    let mut response_headers = HeaderMap::new();
    if let Some((receipt, policy)) = payment.as_ref() {
        if let Err(response) = record_api_payment_response(
            &state,
            &mut response_headers,
            receipt,
            policy,
            started_at_ms,
        )
        .await
        {
            return response;
        }
    }
    (response_headers, Json(response_body)).into_response()
}

async fn authorize_route_payment(
    state: &AppState,
    headers: &HeaderMap,
    policy: Option<api_payments::ApiPaymentRoutePolicy>,
) -> Result<
    Option<(
        api_payments::ApiPaymentReceipt,
        api_payments::ApiPaymentRoutePolicy,
    )>,
    Response,
> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    match api_payments::parse_payment_credential(headers) {
        Ok(Some(api_payments::ApiPaymentCredential::Direct(credential))) => {
            return authorize_direct_route_payment(state, &policy, credential)
                .await
                .map(|receipt| Some((receipt, policy)));
        }
        Ok(Some(api_payments::ApiPaymentCredential::Channel(_))) | Ok(None) => {}
        Err(error) => {
            state
                .payment_metrics
                .authorization_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "api_payments",
                route = %policy.route,
                pricing_id = %policy.pricing_id,
                request_hash = %policy.request_hash,
                failure_code = "invalid-payment-authorization",
                "API payment authorization failed"
            );
            return Err(
                api_payments::ApiPaymentGuardError::InvalidAuthorization(error)
                    .into_response(&policy),
            );
        }
    }
    let Some(p) = state.persister.as_ref() else {
        state
            .payment_metrics
            .authorization_failures
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "api_payments",
            route = %policy.route,
            pricing_id = %policy.pricing_id,
            request_hash = %policy.request_hash,
            failure_code = "payment-persistence-unavailable",
            "API payment authorization failed"
        );
        return Err(
            api_payments::ApiPaymentGuardError::PersistenceUnavailable.into_response(&policy)
        );
    };
    match api_payments::authorize_api_payment(p.pool(), headers, &policy).await {
        Ok(receipt) => Ok(Some((receipt, policy))),
        Err(err) => {
            state
                .payment_metrics
                .authorization_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "api_payments",
                route = %policy.route,
                pricing_id = %policy.pricing_id,
                request_hash = %policy.request_hash,
                failure_code = err.failure_code(),
                "API payment authorization failed"
            );
            Err(err.into_response(&policy))
        }
    }
}

async fn authorize_direct_route_payment(
    state: &AppState,
    policy: &api_payments::ApiPaymentRoutePolicy,
    credential: api_payments::ApiDirectPaymentCredential,
) -> Result<api_payments::ApiPaymentReceipt, Response> {
    let proof_request = match state
        .payment_policy
        .direct_payment_proof_request_for_policy(policy, credential)
    {
        Ok(request) => request,
        Err(error) => {
            return Err(direct_payment_problem(
                StatusCode::BAD_REQUEST,
                "payment-invalid-direct-proof",
                "Invalid Direct Payment Proof",
                Some(error.to_string().as_str()),
            ))
        }
    };
    let amount_sompi = match state
        .payment_policy
        .validate_direct_payment_proof(&proof_request)
    {
        Ok(amount_sompi) if amount_sompi <= i64::MAX as u64 => amount_sompi as i64,
        Ok(_) => {
            return Err(direct_payment_problem(
                StatusCode::BAD_REQUEST,
                "payment-invalid-direct-proof",
                "Invalid Direct Payment Proof",
                Some("amountSompi is too large for storage"),
            ))
        }
        Err(error) => {
            return Err(direct_payment_problem(
                StatusCode::BAD_REQUEST,
                "payment-invalid-direct-proof",
                "Invalid Direct Payment Proof",
                Some(error.to_string().as_str()),
            ))
        }
    };
    let Some(persister) = state.persister.as_ref() else {
        return Err(direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-persistence-unavailable",
            "Payment Persistence Unavailable",
            None,
        ));
    };
    let Some(rest) = state.direct_payment_rest.as_ref() else {
        return Err(direct_payment_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment-direct-verifier-unavailable",
            "Direct Payment Verifier Unavailable",
            Some("API_PAYMENT_REST_URL is not configured"),
        ));
    };

    let submitted_at_ms = now_ms() as i64;
    let row = match db_api_payments::submit_api_direct_payment_proof(
        persister.pool(),
        db_api_payments::NewApiDirectPaymentProof {
            challenge_id: proof_request.challenge_id.clone(),
            network_id: proof_request.network_id.clone(),
            txid_hex: proof_request.txid_hex.clone(),
            payer_identifier: proof_request.payer_identifier.clone(),
            recipient_address: proof_request.recipient_address.clone(),
            amount_sompi,
            pricing_id: proof_request.pricing_id.clone(),
            route: proof_request.route.clone(),
            request_hash: proof_request.request_hash.clone(),
            status: "submitted".to_string(),
            failure_reason: None,
            raw_status_snapshot: None,
            submitted_at_ms,
            verified_at_ms: None,
            indexed_at_ms: None,
        },
    )
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => match db_api_payments::api_direct_payment_proof_by_txid(
            persister.pool(),
            &proof_request.txid_hex,
        )
        .await
        {
            Ok(Some(row))
                if row.challenge_id == proof_request.challenge_id
                    && direct_payment_row_matches_policy(&row, policy) =>
            {
                row
            }
            Ok(Some(_)) => {
                return Err(direct_payment_problem(
                    StatusCode::CONFLICT,
                    "payment-direct-proof-replay",
                    "Direct Payment Proof Replay",
                    Some("txidHex or challengeId was already submitted for a different request"),
                ))
            }
            Ok(None) => {
                return Err(direct_payment_problem(
                    StatusCode::CONFLICT,
                    "payment-direct-proof-replay",
                    "Direct Payment Proof Replay",
                    Some("txidHex or challengeId was already submitted"),
                ))
            }
            Err(error) => {
                return Err(direct_payment_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "payment-direct-proof-read-failed",
                    "Direct Payment Proof Read Failed",
                    Some(error.to_string().as_str()),
                ))
            }
        },
        Err(error) => {
            return Err(direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-direct-proof-submit-failed",
                "Direct Payment Proof Submit Failed",
                Some(error.to_string().as_str()),
            ))
        }
    };

    let tx = match rest.get_transaction(&row.txid_hex).await {
        Ok(tx) => tx,
        Err(error) => {
            return Err(direct_payment_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "payment-direct-tx-lookup-failed",
                "Direct Payment Tx Lookup Failed",
                Some(error.to_string().as_str()),
            ))
        }
    };
    let verification = api_payments::verify_direct_payment_transaction(
        &api_payments::ApiDirectPaymentExpectation {
            challenge_id: row.challenge_id.clone(),
            txid_hex: row.txid_hex.clone(),
            recipient_address: row.recipient_address.clone(),
            amount_sompi: row.amount_sompi.max(0) as u64,
            request_hash: row.request_hash.clone(),
        },
        &tx,
    );
    let verified_at_ms = now_ms() as i64;
    let indexed_at_ms = if verification.status == "accepted" {
        Some(verified_at_ms)
    } else {
        None
    };
    let row = match db_api_payments::update_api_direct_payment_proof_status(
        persister.pool(),
        db_api_payments::ApiDirectPaymentProofStatusUpdate {
            txid_hex: row.txid_hex,
            status: verification.status,
            failure_reason: verification.failure_reason,
            raw_status_snapshot: Some(verification.raw_status_snapshot),
            verified_at_ms,
            indexed_at_ms,
        },
    )
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(direct_payment_problem(
                StatusCode::NOT_FOUND,
                "payment-direct-proof-not-found",
                "Direct Payment Proof Not Found",
                None,
            ))
        }
        Err(error) => {
            return Err(direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-direct-proof-update-failed",
                "Direct Payment Proof Update Failed",
                Some(error.to_string().as_str()),
            ))
        }
    };

    match row.status.as_str() {
        "accepted" => Ok(api_payments::ApiPaymentReceipt {
            receipt_id: direct_payment_receipt_id(&row.txid_hex),
            channel_id: None,
            voucher_sequence: None,
            amount_sompi: row.amount_sompi.max(0) as u64,
            pricing_id: row.pricing_id,
            request_hash: row.request_hash,
            payer_identifier_hash_hex: row
                .payer_identifier
                .as_deref()
                .map(api_payments::payer_identifier_hash_hex),
        }),
        "verified" => Err(direct_payment_problem(
            StatusCode::PAYMENT_REQUIRED,
            "payment-direct-tx-pending",
            "Direct Payment Transaction Pending",
            Some("transaction was found but is not accepted yet"),
        )),
        _ => Err(direct_payment_problem(
            StatusCode::PAYMENT_REQUIRED,
            "payment-direct-tx-rejected",
            "Direct Payment Transaction Rejected",
            row.failure_reason.as_deref(),
        )),
    }
}

fn direct_payment_row_matches_policy(
    row: &db_api_payments::ApiDirectPaymentProofRow,
    policy: &api_payments::ApiPaymentRoutePolicy,
) -> bool {
    row.network_id == policy.network_id
        && row.pricing_id == policy.pricing_id
        && row.route == policy.route
        && row.request_hash == policy.request_hash
        && row.amount_sompi >= policy.amount_sompi as i64
}

async fn record_api_payment_response(
    state: &AppState,
    response_headers: &mut HeaderMap,
    receipt: &api_payments::ApiPaymentReceipt,
    policy: &api_payments::ApiPaymentRoutePolicy,
    started_at_ms: u64,
) -> Result<(), Response> {
    let Some(p) = state.persister.as_ref() else {
        state
            .payment_metrics
            .receipt_record_failures
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "api_payments",
            route = %policy.route,
            pricing_id = %policy.pricing_id,
            request_hash = %policy.request_hash,
            receipt_id = %receipt.receipt_id,
            failure_code = "payment-persistence-unavailable",
            "API payment usage recording failed"
        );
        return Err(
            api_payments::ApiPaymentGuardError::PersistenceUnavailable.into_response(policy)
        );
    };
    let created_at_ms = now_ms();
    let duration_ms = created_at_ms.saturating_sub(started_at_ms);
    match db_api_payments::record_api_payment_usage_event(
        p.pool(),
        db_api_payments::NewApiPaymentUsageEvent {
            request_id: receipt.receipt_id.clone(),
            channel_id: receipt.channel_id.clone(),
            wallet_or_api_key_hash_hex: receipt.payer_identifier_hash_hex.clone(),
            route: policy.route.clone(),
            pricing_id: receipt.pricing_id.clone(),
            amount_sompi: receipt.amount_sompi as i64,
            voucher_sequence: receipt.voucher_sequence.map(|value| value as i64),
            receipt_id: receipt.receipt_id.clone(),
            response_status: Some(StatusCode::OK.as_u16() as i32),
            duration_ms: Some(duration_ms as i64),
            created_at_ms: created_at_ms as i64,
        },
    )
    .await
    {
        Ok(Some(_)) => {
            state
                .payment_metrics
                .paid_requests_served
                .fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                target: "api_payments",
                route = %policy.route,
                pricing_id = %policy.pricing_id,
                request_hash = %policy.request_hash,
                receipt_id = %receipt.receipt_id,
                channel_id = ?receipt.channel_id,
                voucher_sequence = ?receipt.voucher_sequence,
                amount_sompi = receipt.amount_sompi,
                duration_ms,
                "API payment request served"
            );
        }
        Ok(None) => {
            state
                .payment_metrics
                .receipt_record_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "api_payments",
                route = %policy.route,
                pricing_id = %policy.pricing_id,
                request_hash = %policy.request_hash,
                receipt_id = %receipt.receipt_id,
                channel_id = ?receipt.channel_id,
                voucher_sequence = ?receipt.voucher_sequence,
                duration_ms,
                failure_code = "payment-receipt-already-recorded",
                "API payment usage recording failed"
            );
            return Err(direct_payment_problem(
                StatusCode::CONFLICT,
                "payment-receipt-already-recorded",
                "Payment Receipt Already Recorded",
                None,
            ));
        }
        Err(error) => {
            state
                .payment_metrics
                .receipt_record_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "api_payments",
                route = %policy.route,
                pricing_id = %policy.pricing_id,
                request_hash = %policy.request_hash,
                receipt_id = %receipt.receipt_id,
                channel_id = ?receipt.channel_id,
                voucher_sequence = ?receipt.voucher_sequence,
                duration_ms,
                failure_code = "payment-receipt-record-failed",
                error = %error,
                "API payment usage recording failed"
            );
            return Err(direct_payment_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payment-receipt-record-failed",
                "Payment Receipt Record Failed",
                Some(error.to_string().as_str()),
            ));
        }
    }
    if api_payments::insert_payment_receipt_header(response_headers, receipt).is_err() {
        state
            .payment_metrics
            .receipt_encode_failures
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "api_payments",
            route = %policy.route,
            pricing_id = %policy.pricing_id,
            request_hash = %policy.request_hash,
            receipt_id = %receipt.receipt_id,
            failure_code = "payment-receipt-encode-failed",
            "API payment receipt header encoding failed"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode payment receipt".to_string(),
        )
            .into_response());
    }
    Ok(())
}

async fn kcc20_discovery_response(
    state: &AppState,
    q: MarketDiscoveryQuery,
) -> Result<Kcc20DiscoveryResponse, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 discovery requires postgres state".into(),
        ));
    };
    if !repo::kcc20_market_summaries_table_exists(p.pool())
        .await
        .map_err(internal)?
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 discovery requires database migrations".into(),
        ));
    }
    if let Some(token_id) = q.token_id.as_deref() {
        validate_hex_32(token_id, "tokenId")?;
    }
    let sort_by = normalize_discovery_sort_by(q.sort_by.as_deref());
    let sort_direction = normalize_discovery_sort_direction(q.sort_direction.as_deref());
    let limit = bounded_i64(q.limit, 50, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let started = Instant::now();
    let page = repo::kcc20_market_discovery(
        p.pool(),
        q.token_id.as_deref(),
        &sort_by,
        &sort_direction,
        limit,
        offset,
        q.include_total.unwrap_or(true),
    )
    .await
    .map_err(internal)?;
    let query_duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    Ok(Kcc20DiscoveryResponse {
        items: page.items,
        total: page.total,
        limit,
        offset,
        sort_by,
        sort_direction,
        query_duration_ms,
        freshness: page.freshness,
    })
}

async fn kcc20_market_snapshots(
    State(state): State<AppState>,
    Query(q): Query<MarketSnapshotsQuery>,
) -> Result<(HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 market snapshots require postgres state".into(),
        ));
    };
    let windows = parse_windows(q.windows.as_deref())?;
    let trade_summaries = repo::kcc20_trade_summaries(p.pool())
        .await
        .map_err(internal)?;
    let page_limit = q.limit.unwrap_or(50).min(50);
    let (tokens, total) = slice_with_total(
        trade_summaries,
        &PaginationQuery {
            limit: Some(page_limit),
            offset: q.offset,
            include_coverage: false,
        },
    );
    let mut rows = Vec::new();
    for summary in tokens {
        for window_ms in &windows {
            let stats = repo::kcc20_token_stats(p.pool(), &summary.token_id_hex, *window_ms)
                .await
                .map_err(internal)?;
            rows.push(Kcc20MarketSnapshotRow {
                token_id_hex: summary.token_id_hex.clone(),
                window_ms: *window_ms,
                volume_sompi: stats.volume_sompi,
                token_volume: stats.token_volume,
                trade_count: stats.trade_count,
                price_change_sompi: stats.price_change_sompi,
                open_unit_price_sompi: stats.open_unit_price_sompi,
                high_unit_price_sompi: stats.high_unit_price_sompi,
                low_unit_price_sompi: stats.low_unit_price_sompi,
                close_unit_price_sompi: stats.close_unit_price_sompi,
                last_trade_txid_hex: summary.last_trade_txid_hex.clone(),
                last_trade_time_ms: summary.last_trade_time_ms,
            });
        }
    }
    Ok((
        total_count_header(total),
        Json(serde_json::to_value(rows).map_err(internal)?),
    ))
}

async fn kcc20_freshness(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "KCC20 freshness requires postgres state".into(),
        ));
    };
    let freshness = repo::kcc20_fast_freshness(p.pool())
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::to_value(freshness).map_err(internal)?))
}

fn filter_listings_with_total(
    mut rows: Vec<repo::Kcc20ListingRow>,
    q: &MarketRowsQuery,
) -> (Vec<repo::Kcc20ListingRow>, i64) {
    if let Some(status) = q.status.as_deref() {
        rows.retain(|row| row.status == status);
    }
    match q.sort.as_deref() {
        Some("price_desc") => rows.sort_by(|a, b| {
            cmp_numeric_desc(
                a.unit_price_sompi.as_ref().or(a.price_sompi.as_ref()),
                b.unit_price_sompi.as_ref().or(b.price_sompi.as_ref()),
            )
        }),
        Some("created_asc") => rows.sort_by_key(|row| row.created_at_ms),
        Some("created_desc") | None => rows.sort_by_key(|row| std::cmp::Reverse(row.created_at_ms)),
        _ => rows.sort_by(|a, b| {
            cmp_numeric_asc(
                a.unit_price_sompi.as_ref().or(a.price_sompi.as_ref()),
                b.unit_price_sompi.as_ref().or(b.price_sompi.as_ref()),
            )
        }),
    }
    let total = rows.len() as i64;
    let paged = paginate(rows, q.offset.unwrap_or(0), q.limit);
    (paged, total)
}

fn filter_listings(
    rows: Vec<repo::Kcc20ListingRow>,
    q: &MarketRowsQuery,
) -> Vec<repo::Kcc20ListingRow> {
    filter_listings_with_total(rows, q).0
}

fn filter_listings_for_depth(
    mut rows: Vec<repo::Kcc20ListingRow>,
    q: &MarketRowsQuery,
) -> Vec<repo::Kcc20ListingRow> {
    if let Some(status) = q.status.as_deref() {
        rows.retain(|row| row.status == status);
    }
    rows
}

fn filter_bids_with_total(
    mut rows: Vec<repo::Kcc20BidRow>,
    q: &MarketRowsQuery,
) -> (Vec<repo::Kcc20BidRow>, i64) {
    if let Some(status) = q.status.as_deref() {
        rows.retain(|row| row.status == status);
    }
    match q.sort.as_deref() {
        Some("price_asc") => rows.sort_by(|a, b| {
            cmp_numeric_asc(
                a.unit_price_sompi.as_ref().or(a.price_sompi.as_ref()),
                b.unit_price_sompi.as_ref().or(b.price_sompi.as_ref()),
            )
        }),
        Some("created_asc") => rows.sort_by_key(|row| row.created_at_ms),
        Some("created_desc") | None => rows.sort_by_key(|row| std::cmp::Reverse(row.created_at_ms)),
        _ => rows.sort_by(|a, b| {
            cmp_numeric_desc(
                a.unit_price_sompi.as_ref().or(a.price_sompi.as_ref()),
                b.unit_price_sompi.as_ref().or(b.price_sompi.as_ref()),
            )
        }),
    }
    let total = rows.len() as i64;
    let paged = paginate(rows, q.offset.unwrap_or(0), q.limit);
    (paged, total)
}

fn filter_bids(rows: Vec<repo::Kcc20BidRow>, q: &MarketRowsQuery) -> Vec<repo::Kcc20BidRow> {
    filter_bids_with_total(rows, q).0
}

fn filter_bids_for_depth(
    mut rows: Vec<repo::Kcc20BidRow>,
    q: &MarketRowsQuery,
) -> Vec<repo::Kcc20BidRow> {
    if let Some(status) = q.status.as_deref() {
        rows.retain(|row| row.status == status);
    }
    rows
}

fn orderbook_depth_limit(q: &MarketRowsQuery) -> usize {
    q.depth_limit
        .unwrap_or(DEFAULT_ORDERBOOK_DEPTH_LIMIT)
        .clamp(1, MAX_ORDERBOOK_DEPTH_LIMIT)
}

fn paginate<T>(rows: Vec<T>, offset: usize, limit: Option<usize>) -> Vec<T> {
    rows.into_iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

#[derive(Debug, Default, Deserialize)]
struct PaginationQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default, rename = "includeCoverage")]
    include_coverage: bool,
}

fn usize_as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn bounded_usize_as_i64(value: Option<usize>, default: i64, max: i64) -> i64 {
    bounded_i64(value.map(usize_as_i64), default, max)
}

/// Slice an in-memory Vec for an HTTP page and return the pre-paging length
/// so the handler can emit `X-Total-Count`. Use when the underlying repo
/// query already returns a bounded, fully-materialised result.
fn slice_with_total<T>(rows: Vec<T>, q: &PaginationQuery) -> (Vec<T>, i64) {
    let total = rows.len() as i64;
    let paged = paginate(rows, q.offset.unwrap_or(0), q.limit);
    (paged, total)
}

fn ask_depth(asks: &[repo::Kcc20ListingRow], limit: usize) -> Vec<DepthLevel> {
    let mut depth: BTreeMap<i128, (i128, usize)> = BTreeMap::new();
    for ask in asks {
        let Some(price) = ask.unit_price_sompi.as_ref().or(ask.price_sompi.as_ref()) else {
            continue;
        };
        let Some(price) = parse_i128(Some(price)) else {
            continue;
        };
        let amount = parse_i128(
            ask.locked_token_amount
                .as_deref()
                .or(ask.token_amount.as_deref()),
        )
        .unwrap_or(0);
        if price <= 0 || amount <= 0 {
            continue;
        }
        let entry = depth.entry(price).or_insert((0, 0));
        entry.0 += amount;
        entry.1 += 1;
    }
    depth
        .into_iter()
        .take(limit)
        .map(|(price, (amount, count))| DepthLevel {
            unit_price_sompi: price.to_string(),
            token_amount: amount.to_string(),
            order_count: count,
        })
        .collect()
}

fn bid_depth(bids: &[repo::Kcc20BidRow], limit: usize) -> Vec<DepthLevel> {
    let mut depth: BTreeMap<i128, (i128, usize)> = BTreeMap::new();
    for bid in bids {
        let Some(price) = bid.unit_price_sompi.as_ref().or(bid.price_sompi.as_ref()) else {
            continue;
        };
        let Some(price) = parse_i128(Some(price)) else {
            continue;
        };
        let amount = parse_i128(bid.token_amount.as_deref()).unwrap_or(0);
        if price <= 0 || amount <= 0 {
            continue;
        }
        let entry = depth.entry(price).or_insert((0, 0));
        entry.0 += amount;
        entry.1 += 1;
    }
    depth
        .into_iter()
        .rev()
        .take(limit)
        .map(|(price, (amount, count))| DepthLevel {
            unit_price_sompi: price.to_string(),
            token_amount: amount.to_string(),
            order_count: count,
        })
        .collect()
}

fn sum_ask_tokens(asks: &[repo::Kcc20ListingRow]) -> i128 {
    asks.iter()
        .map(|ask| {
            parse_i128(
                ask.locked_token_amount
                    .as_deref()
                    .or(ask.token_amount.as_deref()),
            )
            .unwrap_or(0)
        })
        .sum()
}

fn sum_bid_tokens(bids: &[repo::Kcc20BidRow]) -> i128 {
    bids.iter()
        .map(|bid| parse_i128(bid.token_amount.as_deref()).unwrap_or(0))
        .sum()
}

fn sum_ask_value(asks: &[repo::Kcc20ListingRow]) -> i128 {
    asks.iter()
        .map(|ask| {
            let amount = parse_i128(
                ask.locked_token_amount
                    .as_deref()
                    .or(ask.token_amount.as_deref()),
            )
            .unwrap_or(0);
            if let Some(unit_price) = parse_i128(ask.unit_price_sompi.as_deref()) {
                amount * unit_price
            } else {
                parse_i128(ask.price_sompi.as_deref()).unwrap_or(0)
            }
        })
        .sum()
}

fn sum_bid_value(bids: &[repo::Kcc20BidRow]) -> i128 {
    bids.iter()
        .map(|bid| {
            bid.bid_value_sompi
                .as_deref()
                .and_then(|value| value.parse::<i128>().ok())
                .unwrap_or_else(|| {
                    if let Some(unit_price) = parse_i128(bid.unit_price_sompi.as_deref()) {
                        parse_i128(bid.token_amount.as_deref()).unwrap_or(0) * unit_price
                    } else {
                        parse_i128(bid.price_sompi.as_deref()).unwrap_or(0)
                    }
                })
        })
        .sum()
}

fn unit_price_from_order(
    unit_price_sompi: Option<&str>,
    total_price_sompi: Option<&str>,
    amount: Option<&str>,
) -> Option<String> {
    if let Some(unit_price) = unit_price_sompi.and_then(|value| parse_i128(Some(value))) {
        return Some(unit_price.to_string());
    }
    let total = total_price_sompi.and_then(|value| parse_i128(Some(value)))?;
    let amount = amount.and_then(|value| parse_i128(Some(value)))?;
    if amount <= 0 {
        return None;
    }
    Some((total / amount).to_string())
}

fn build_quote(
    token_id_hex: &str,
    side: &str,
    requested: i128,
    order_id: Option<String>,
    ask: Option<&repo::Kcc20ListingRow>,
    bid: Option<&repo::Kcc20BidRow>,
    mut errors: Vec<String>,
) -> Kcc20QuoteResponse {
    let (selected_order_id, available_amount, min_fill_amount, unit_price_sompi, fee_ticket_id) =
        if let Some(ask) = ask {
            let available_amount = ask.locked_token_amount.clone().or(ask.token_amount.clone());
            (
                Some(ask.order_id.clone()),
                available_amount.clone(),
                ask.min_fill_amount.clone(),
                unit_price_from_order(
                    ask.unit_price_sompi.as_deref(),
                    ask.price_sompi.as_deref(),
                    available_amount.as_deref(),
                ),
                ask.fee_ticket_id.clone(),
            )
        } else if let Some(bid) = bid {
            (
                Some(bid.order_id.clone()),
                bid.token_amount.clone(),
                bid.min_fill_amount.clone(),
                unit_price_from_order(
                    bid.unit_price_sompi.as_deref(),
                    bid.bid_value_sompi
                        .as_deref()
                        .or(bid.price_sompi.as_deref()),
                    bid.token_amount.as_deref(),
                ),
                bid.fee_ticket_id.clone(),
            )
        } else {
            errors.push("no matching open order".to_string());
            (order_id, None, None, None, None)
        };

    let available = parse_i128(available_amount.as_deref());
    let min_fill = parse_i128(min_fill_amount.as_deref()).unwrap_or(1);
    let unit_price = parse_i128(unit_price_sompi.as_deref());
    if let Some(available) = available {
        if requested > available {
            errors.push("amount exceeds available order amount".to_string());
        }
    }
    if requested > 0 && requested < min_fill {
        errors.push("amount is below order min fill".to_string());
    }
    let total_price_sompi = match (unit_price, requested > 0) {
        (Some(unit_price), true) => Some((unit_price * requested).to_string()),
        _ => None,
    };
    Kcc20QuoteResponse {
        token_id_hex: token_id_hex.to_string(),
        side: side.to_string(),
        order_id: selected_order_id,
        valid: errors.is_empty(),
        errors,
        requested_amount: requested.to_string(),
        available_amount,
        min_fill_amount,
        unit_price_sompi,
        total_price_sompi,
        fee_ticket_id,
    }
}

async fn build_orderbook_order_lineage(
    persister: &PgPersister,
    token_id_hex: &str,
    order_id: &str,
) -> std::result::Result<Vec<serde_json::Value>, (StatusCode, String)> {
    let Some((mut txid, mut vout)) = parse_order_outpoint(order_id) else {
        return Ok(Vec::new());
    };
    let mut lineage = Vec::new();
    for _ in 0..32 {
        let actions = repo::actions_by_txid(persister.pool(), &txid)
            .await
            .map_err(internal)?;
        let output = actions
            .iter()
            .find(|action| {
                action.covenant_id_hex == token_id_hex
                    && action.action == "continuation"
                    && action
                        .outputs
                        .as_ref()
                        .and_then(|outputs| outputs.get("vout"))
                        .and_then(|v| v.as_i64())
                        == Some(i64::from(vout))
            })
            .and_then(|action| action.outputs.clone());
        let spend = actions.iter().find(|action| {
            action.covenant_id_hex == token_id_hex
                && action.action == "spend"
                && action.entrypoint.is_some()
        });
        lineage.push(json!({
            "orderId": format!("{txid}:{vout}"),
            "txidHex": txid,
            "vout": vout,
            "state": output.as_ref().and_then(|value| value.get("state")).cloned(),
            "address": output.as_ref().and_then(|value| value.get("address")).cloned(),
            "amountSompi": output.as_ref().and_then(|value| value.get("amountSompi")).cloned(),
            "entrypoint": spend.and_then(|action| action.entrypoint.clone()),
            "blockTimeMs": spend.map(|action| action.block_time_ms),
            "fillTxidHex": spend.map(|action| action.txid_hex.clone()),
            "previousOutpoint": spend.and_then(|action| action.inputs.clone()).and_then(|inputs| inputs.get("previousOutpoint").cloned()),
        }));
        let Some(spend) = spend else {
            break;
        };
        let previous = spend
            .inputs
            .as_ref()
            .and_then(|inputs| inputs.get("previousOutpoint"));
        let Some(parent_txid) = previous
            .and_then(|previous| previous.get("hash"))
            .and_then(|hash| hash.as_str())
            .map(str::to_string)
        else {
            break;
        };
        let Some(parent_vout) = previous
            .and_then(|previous| previous.get("index"))
            .and_then(|index| index.as_i64())
            .and_then(|index| i32::try_from(index).ok())
        else {
            break;
        };
        if parent_txid == txid && parent_vout == vout {
            break;
        }
        txid = parent_txid;
        vout = parent_vout;
    }
    lineage.reverse();
    Ok(lineage)
}

fn parse_order_outpoint(order_id: &str) -> Option<(String, i32)> {
    let (txid, vout) = order_id.split_once(':')?;
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((txid.to_string(), vout.parse().ok()?))
}

fn cmp_numeric_asc(a: Option<&String>, b: Option<&String>) -> std::cmp::Ordering {
    parse_i128(a.map(String::as_str)).cmp(&parse_i128(b.map(String::as_str)))
}

fn cmp_numeric_desc(a: Option<&String>, b: Option<&String>) -> std::cmp::Ordering {
    cmp_numeric_asc(b, a)
}

fn parse_i128(value: Option<&str>) -> Option<i128> {
    value?.parse::<i128>().ok()
}

fn parse_windows(value: Option<&str>) -> Result<Vec<i64>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(vec![86_400_000, 604_800_000]);
    };
    let mut windows = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let parsed = raw.parse::<i64>().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "windows must be comma-separated positive millisecond integers".into(),
            )
        })?;
        if parsed <= 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                "windows must be positive millisecond integers".into(),
            ));
        }
        windows.push(parsed);
    }
    if windows.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "windows must include at least one value".into(),
        ));
    }
    if windows.len() > 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "windows accepts at most four values".into(),
        ));
    }
    Ok(windows)
}

fn bounded_i64(value: Option<i64>, default: i64, max: i64) -> i64 {
    value.unwrap_or(default).clamp(0, max)
}

fn normalize_discovery_sort_by(value: Option<&str>) -> String {
    match value.unwrap_or("lastTradeTimeMs") {
        "tokenId" | "tokenIdHex" => "tokenIdHex",
        "bestAskUnitPriceSompi" => "bestAskUnitPriceSompi",
        "bestBidUnitPriceSompi" => "bestBidUnitPriceSompi",
        "spreadSompi" => "spreadSompi",
        "openAskCount" => "openAskCount",
        "openBidCount" => "openBidCount",
        "totalVolumeSompi" => "totalVolumeSompi",
        "totalTrades" => "totalTrades",
        "volume24hSompi" => "volume24hSompi",
        "volume7dSompi" => "volume7dSompi",
        "tradeCount24h" => "tradeCount24h",
        "tradeCount7d" => "tradeCount7d",
        "lastTradeTimeMs" => "lastTradeTimeMs",
        _ => "lastTradeTimeMs",
    }
    .to_string()
}

fn normalize_discovery_sort_direction(value: Option<&str>) -> String {
    if value
        .map(|v| v.eq_ignore_ascii_case("asc"))
        .unwrap_or(false)
    {
        "asc"
    } else {
        "desc"
    }
    .to_string()
}

fn normalize_portfolio_asset_sort_by(value: Option<&str>) -> Option<&'static str> {
    match value.unwrap_or("canonicalTokenIdHex") {
        "canonicalTokenIdHex" => Some("canonicalTokenIdHex"),
        "nativeBalance" => Some("nativeBalance"),
        "orderbookBalance" => Some("orderbookBalance"),
        "totalBalance" => Some("totalBalance"),
        "assetUtxoCount" => Some("assetUtxoCount"),
        "openAskAmount" => Some("openAskAmount"),
        "openBidAmount" => Some("openBidAmount"),
        "openOrderCount" => Some("openOrderCount"),
        "lastChangeMs" => Some("lastChangeMs"),
        "bestAskUnitPriceSompi" => Some("bestAskUnitPriceSompi"),
        "valueSompi" => Some("valueSompi"),
        _ => None,
    }
}

fn normalize_portfolio_asset_sort_direction(value: Option<&str>) -> Option<&'static str> {
    match value.unwrap_or("asc") {
        "asc" => Some("asc"),
        "desc" => Some("desc"),
        _ => None,
    }
}

fn portfolio_asset_query_bool(
    name: &str,
    value: Option<&str>,
) -> Result<bool, (StatusCode, String)> {
    match value.unwrap_or("false") {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("{name} must be true, false, 1, or 0"),
        )),
    }
}

fn portfolio_asset_page_bounds(
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(i64, i64), (StatusCode, String)> {
    let limit = limit.unwrap_or(10);
    if !(1..=1_000).contains(&limit) {
        return Err((
            StatusCode::BAD_REQUEST,
            "limit must be between 1 and 1000".into(),
        ));
    }
    let offset = offset.unwrap_or(0);
    if offset < 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "offset must be zero or greater".into(),
        ));
    }
    Ok((limit, offset))
}

fn validate_portfolio_asset_search(search: Option<&str>) -> Result<(), (StatusCode, String)> {
    if search.is_some_and(|value| value.chars().count() > 64) {
        return Err((
            StatusCode::BAD_REQUEST,
            "search accepts at most 64 characters".into(),
        ));
    }
    if search.is_some_and(|value| value.contains('\0')) {
        return Err((
            StatusCode::BAD_REQUEST,
            "search must not contain NUL characters".into(),
        ));
    }
    Ok(())
}

fn validate_owner_query(owner: Option<&str>) -> Result<(), (StatusCode, String)> {
    let Some(owner) = owner else {
        return Ok(());
    };
    if owner.len() == 64 && owner.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        "KCC20 owner lookup currently expects a 32-byte owner identifier hex".into(),
    ))
}

fn kcc20_owner_lookup(value: &str) -> Result<Kcc20OwnerLookup, (StatusCode, String)> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Kcc20OwnerLookup::OwnerIdentifierHex(
            value.to_ascii_lowercase(),
        ));
    }
    let address = Address::try_from(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "address must be a 32-byte owner identifier hex or a valid Kaspa address".into(),
        )
    })?;
    match address.version {
        Version::PubKey if address.payload.len() == 32 => {
            Ok(Kcc20OwnerLookup::OwnerIdentifierHex(hex::encode(
                address.payload.as_slice(),
            )))
        }
        Version::ScriptHash => Ok(Kcc20OwnerLookup::CovenantAddress(value.to_string())),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "KCC20 owner lookup supports 32-byte pubkey addresses or covenant script-hash addresses".into(),
        )),
    }
}

fn kcc20_owner_identifier_lookup(value: &str, label: &str) -> Result<String, (StatusCode, String)> {
    match kcc20_owner_lookup(value)? {
        Kcc20OwnerLookup::OwnerIdentifierHex(owner) => Ok(owner),
        Kcc20OwnerLookup::CovenantAddress(_) => Err((
            StatusCode::BAD_REQUEST,
            format!("KCC20 {label} expects a 32-byte owner identifier hex or pubkey address"),
        )),
    }
}

fn validate_hex_32(value: &str, label: &str) -> Result<(), (StatusCode, String)> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{label} must be 32-byte hex"),
    ))
}

fn is_channel_receipt_id(value: &str) -> bool {
    value
        .strip_prefix("apr_")
        .map(|hash| hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

fn direct_payment_receipt_id(txid_hex: &str) -> String {
    format!("apd_{txid_hex}")
}

fn direct_receipt_txid(value: &str) -> Option<&str> {
    value
        .strip_prefix("apd_")
        .filter(|txid| txid.len() == 64 && txid.chars().all(|c| c.is_ascii_hexdigit()))
}

fn validate_trade_side(side: Option<&str>) -> Result<(), (StatusCode, String)> {
    match side {
        None | Some("buy") | Some("sell") | Some("cross") | Some("trade") => Ok(()),
        Some(_) => Err((
            StatusCode::BAD_REQUEST,
            "side must be one of buy, sell, cross, or trade".into(),
        )),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ListEventsQuery {
    limit: Option<i64>,
    /// Filter by row classification: covenant, inscription, or unknown.
    classification: Option<String>,
    /// Filter by reveal status: unrevealed, matched, or unmatched.
    #[serde(rename = "classificationStatus")]
    classification_status: Option<String>,
}

async fn list_events(
    State(state): State<AppState>,
    Query(q): Query<ListEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = bounded_i64(q.limit, 200, 500);
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::recent_actions(
            p.pool(),
            limit,
            q.classification.as_deref(),
            q.classification_status.as_deref(),
        )
        .await
        .map_err(internal)?;
        return Ok(Json(serde_json::to_value(rows).map_err(internal)?));
    }
    let holder = state.inner.read().await;
    Ok(Json(
        serde_json::to_value(holder.snapshot().events).map_err(internal)?,
    ))
}

async fn events_by_txid(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(p) = state.persister.as_ref() {
        let rows = repo::actions_by_txid(p.pool(), &txid)
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::to_value(rows).map_err(internal)?));
    }
    let holder = state.inner.read().await;
    let matched: Vec<CovenantEvent> = holder
        .snapshot()
        .events
        .into_iter()
        .filter(|e| e.txid == txid)
        .collect();
    Ok(Json(serde_json::to_value(matched).map_err(internal)?))
}

async fn tx_settlement_status(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "txid must be 32-byte hex".into()));
    }
    let Some(p) = state.persister.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "tx settlement status requires postgres state".into(),
        ));
    };
    let rows = repo::actions_by_txid(p.pool(), &txid)
        .await
        .map_err(internal)?;
    let scanner = repo::scanner_health(p.pool()).await.map_err(internal)?;
    let action_count = rows.len();
    let spend_count = rows.iter().filter(|row| row.action == "spend").count();
    let continuation_count = rows
        .iter()
        .filter(|row| row.action == "continuation")
        .count();
    let matched_count = rows
        .iter()
        .filter(|row| row.classification_status == "matched")
        .count();
    let decoded_count = rows.iter().filter(|row| row.entrypoint.is_some()).count();
    let block_time_ms = rows.iter().map(|row| row.block_time_ms).max();
    Ok(Json(json!({
        "txidHex": txid,
        "indexed": action_count > 0,
        "decoded": decoded_count > 0,
        "actionCount": action_count,
        "spendCount": spend_count,
        "continuationCount": continuation_count,
        "matchedCovenantCount": matched_count,
        "blockTimeMs": block_time_ms,
        "scanner": scanner,
        "actions": rows,
    })))
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    mod shadow_contract_tests { include!("shadow_contract_tests.rs"); }
    #[test]
    fn secret_environment_values_are_hidden_in_help() {
        use clap::CommandFactory;
        let command = super::Cli::command();
        for key in ["DATABASE_URL", "API_PAYMENT_CHANNEL_SYNC_BEARER_TOKEN"] {
            let arg = command
                .get_arguments()
                .find(|arg| arg.get_env() == Some(std::ffi::OsStr::new(key)))
                .expect("secret argument exists");
            assert!(arg.is_hide_env_values_set(), "{key}");
        }
    }

    use super::*;
    use std::sync::atomic::AtomicUsize;

    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use kaspa_addresses::Prefix;
    use secp256k1::{Keypair, Message};
    use sqlx::PgPool;
    use tn12_indexer_core::{
        ApiPaymentChannelCloseRequest, ApiPaymentMethod, ApiPaymentVoucher, RestTxOutput,
        API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1, API_PAYMENT_VOUCHER_SCHEMA_V1,
    };
    use tn12_indexer_crawl::source_observation::NodeObservation;
    use tn12_indexer_db::api_payments::{
        apply_indexed_api_payment_channel_settlement, insert_api_payment_channel,
        upsert_indexed_api_payment_channel_open, IndexedApiPaymentChannelOpen,
        IndexedApiPaymentChannelSettlement, NewApiPaymentChannel,
    };
    use tower::ServiceExt;

    #[test]
    fn caught_up_cursor_requires_verification_at_the_new_watermark() {
        let checkpoint = json!({"verified": true, "verifiedThroughBlueScore": 100});
        assert!(checkpoint_verifies_tip(Some(&checkpoint), Some(100)));
        assert!(!checkpoint_verifies_tip(Some(&checkpoint), Some(106)));
        assert_eq!(
            history_coverage_phase(
                checkpoint_verifies_tip(Some(&checkpoint), Some(106)),
                Some(106),
                Some(0),
                Some(0)
            ),
            ("incomplete", "verifying")
        );
        let verified = json!({"verified": true, "verifiedThroughBlueScore": 106});
        assert!(checkpoint_verifies_tip(Some(&verified), Some(106)));
        assert!(!checkpoint_verifies_tip(Some(&verified), None));
        assert!(!checkpoint_verifies_tip(
            Some(&json!({"verified":true})),
            Some(106)
        ));
    }

    #[test]
    fn verified_history_becomes_incomplete_when_a_new_gap_opens() {
        assert_eq!(
            history_coverage_phase(false, Some(100), Some(0), Some(0)),
            ("incomplete", "verifying")
        );
        assert_eq!(
            history_coverage_phase(true, Some(100), Some(6), Some(5_000)),
            ("incomplete", "running")
        );
        assert_eq!(
            history_coverage_phase(true, Some(100), Some(0), Some(5_000)),
            ("complete", "verified")
        );
        assert_eq!(
            history_coverage_phase(true, Some(100), Some(0), Some(121_000)),
            ("incomplete", "stalled")
        );
        assert_eq!(
            history_coverage_phase(true, None, None, None),
            ("incomplete", "uninitialized")
        );
        assert_eq!(
            history_coverage_phase(false, Some(100), Some(25), Some(121_000)),
            ("incomplete", "stalled")
        );
    }

    #[test]
    fn history_rate_uses_a_minute_of_progress_instead_of_single_window_samples() {
        let started = Instant::now();
        let mut sample = None;
        assert_eq!(measured_history_rate(&mut sample, 100, 200, started), None);
        assert_eq!(
            measured_history_rate(&mut sample, 110, 210, started + Duration::from_secs(10)),
            None
        );
        assert_eq!(
            measured_history_rate(&mut sample, 160, 230, started + Duration::from_secs(60)),
            Some(0.5)
        );
        assert_eq!(
            measured_history_rate(&mut sample, 170, 240, started + Duration::from_secs(65)),
            Some(0.5)
        );
    }

    #[tokio::test]
    async fn history_source_tip_uses_fresh_node_observation_and_never_rest() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let rest_app = Router::new().route(
            "/info/health",
            get({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        Json(json!({"database": {"blueScore": 321, "isSynced": true}}))
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, rest_app).await.unwrap() });
        let state = test_state_with_rest(
            None,
            direct_policy(),
            Some(RestClient::new(format!("http://{address}")).unwrap()),
        );
        assert_eq!(current_node_source_tip(&state).await, None);
        *state.source_observation.lock().unwrap() = Some(NodeObservation {
            endpoint: "wss://node/testnet-10".into(),
            network: "testnet-10".into(),
            blue_score: 654,
            observed_at_ms: now_ms() as i64,
            synced: true,
        });
        assert_eq!(current_node_source_tip(&state).await, Some(654));
        state
            .source_observation
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .observed_at_ms -= 16_000;
        assert_eq!(current_node_source_tip(&state).await, None);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        server.abort();
    }

    #[test]
    fn covenant_list_limit_is_bounded() {
        assert_eq!(covenant_list_limit(None), 50);
        assert_eq!(covenant_list_limit(Some(0)), 0);
        assert_eq!(covenant_list_limit(Some(125)), 125);
        assert_eq!(covenant_list_limit(Some(10_000)), 200);
        assert_eq!(covenant_list_limit(Some(-1)), 0);
    }

    #[test]
    fn high_cardinality_query_controls_are_bounded() {
        assert_eq!(
            bounded_market_rows_page(MarketRowsQuery::default()).limit,
            Some(100)
        );
        assert_eq!(
            bounded_market_rows_page(MarketRowsQuery {
                limit: Some(50_000),
                ..Default::default()
            })
            .limit,
            Some(500)
        );
        assert!(parse_windows(Some("1,2,3,4")).is_ok());
        assert!(parse_windows(Some("1,2,3,4,5")).is_err());
        assert!(comma_separated_values(Some(&vec!["x"; 17].join(","))).is_err());
    }

    #[test]
    fn portfolio_asset_sort_controls_are_allowlisted() {
        assert_eq!(
            normalize_portfolio_asset_sort_by(None),
            Some("canonicalTokenIdHex")
        );
        assert_eq!(
            normalize_portfolio_asset_sort_by(Some("valueSompi")),
            Some("valueSompi")
        );
        assert_eq!(
            normalize_portfolio_asset_sort_by(Some("valueSompi DESC; DROP TABLE blocks")),
            None
        );
        assert_eq!(normalize_portfolio_asset_sort_direction(None), Some("asc"));
        assert_eq!(
            normalize_portfolio_asset_sort_direction(Some("desc")),
            Some("desc")
        );
        assert_eq!(normalize_portfolio_asset_sort_direction(Some("DESC")), None);
        assert_eq!(portfolio_asset_query_bool("filter", None).unwrap(), false);
        assert_eq!(
            portfolio_asset_query_bool("filter", Some("1")).unwrap(),
            true
        );
        assert_eq!(
            portfolio_asset_query_bool("filter", Some("0")).unwrap(),
            false
        );
        assert!(portfolio_asset_query_bool("filter", Some("yes")).is_err());
        assert_eq!(portfolio_asset_page_bounds(None, None).unwrap(), (10, 0));
        assert_eq!(
            portfolio_asset_page_bounds(Some(1_000), Some(5)).unwrap(),
            (1_000, 5)
        );
        assert!(portfolio_asset_page_bounds(Some(0), None).is_err());
        assert!(portfolio_asset_page_bounds(Some(1_001), None).is_err());
        assert!(portfolio_asset_page_bounds(None, Some(-1)).is_err());
        assert!(validate_portfolio_asset_search(Some(&"x".repeat(65))).is_err());
        assert!(validate_portfolio_asset_search(Some("nul\0byte")).is_err());
        assert!(validate_portfolio_asset_search(Some(&"é".repeat(64))).is_ok());
    }

    #[test]
    fn kcc20_owner_lookup_maps_pubkey_address_to_owner_identifier() {
        let address = Address::new(Prefix::Testnet, Version::PubKey, &[0u8; 32]).to_string();
        assert_eq!(
            kcc20_owner_lookup(&address).unwrap(),
            Kcc20OwnerLookup::OwnerIdentifierHex("00".repeat(32))
        );
    }

    #[test]
    fn kcc20_owner_lookup_preserves_script_hash_address_lookup() {
        let address = Address::new(Prefix::Testnet, Version::ScriptHash, &[1u8; 32]).to_string();
        assert_eq!(
            kcc20_owner_lookup(&address).unwrap(),
            Kcc20OwnerLookup::CovenantAddress(address)
        );
    }

    #[test]
    fn kcc20_owner_lookup_lowercases_owner_hex() {
        assert_eq!(
            kcc20_owner_lookup(&"AA".repeat(32)).unwrap(),
            Kcc20OwnerLookup::OwnerIdentifierHex("aa".repeat(32))
        );
    }

    #[test]
    fn wallet_identity_values_maps_pubkey_hex_to_testnet_address() {
        let values = wallet_identity_values(
            "f952cc2af7b2c1e1a7ded898eeff5a9a8ed710f3c8e11ffea5353cd8a3f8d32f",
            "testnet-10",
        );
        assert!(values.contains(
            &"kaspatest:qru49np277evrcd8mmvf3mhlt2dga4cs70ywz8l7556nek9rlrfj7w043aq6v".to_string()
        ));
    }

    #[test]
    fn wallet_identity_values_maps_pubkey_address_to_hex() {
        let values = wallet_identity_values(
            "kaspatest:qru49np277evrcd8mmvf3mhlt2dga4cs70ywz8l7556nek9rlrfj7w043aq6v",
            "testnet-10",
        );
        assert!(values.contains(
            &"f952cc2af7b2c1e1a7ded898eeff5a9a8ed710f3c8e11ffea5353cd8a3f8d32f".to_string()
        ));
    }

    #[test]
    fn kcc20_depth_aggregates_duplicate_prices_and_sorts_numerically() {
        let asks = vec![
            listing_row("open", "10", "7", 1),
            listing_row("open", "9", "5", 2),
            listing_row("open", "10", "3", 3),
            listing_row("open", "0", "100", 4),
            listing_row("open", "bad", "100", 5),
        ];
        let ask_depth = ask_depth(&asks, MAX_ORDERBOOK_DEPTH_LIMIT);
        assert_eq!(
            ask_depth
                .iter()
                .map(|row| (
                    row.unit_price_sompi.as_str(),
                    row.token_amount.as_str(),
                    row.order_count
                ))
                .collect::<Vec<_>>(),
            vec![("9", "5", 1), ("10", "10", 2)]
        );

        let bids = vec![
            bid_row("open", "10", "7", 1),
            bid_row("open", "9", "5", 2),
            bid_row("open", "10", "3", 3),
            bid_row("open", "11", "0", 4),
            bid_row("open", "bad", "100", 5),
        ];
        let bid_depth = bid_depth(&bids, MAX_ORDERBOOK_DEPTH_LIMIT);
        assert_eq!(
            bid_depth
                .iter()
                .map(|row| (
                    row.unit_price_sompi.as_str(),
                    row.token_amount.as_str(),
                    row.order_count
                ))
                .collect::<Vec<_>>(),
            vec![("10", "10", 2), ("9", "5", 1)]
        );
    }

    #[test]
    fn kcc20_depth_filters_status_before_paging_and_applies_depth_limit() {
        let query = MarketRowsQuery {
            status: Some("open".to_string()),
            sort: Some("price_desc".to_string()),
            limit: Some(1),
            offset: Some(1),
            depth_limit: Some(2),
        };
        let asks = vec![
            listing_row("open", "10", "7", 1),
            listing_row("open", "9", "5", 2),
            listing_row("open", "8", "3", 3),
            listing_row("closed", "7", "100", 4),
        ];
        let paged = filter_listings(asks.clone(), &query);
        assert_eq!(paged.len(), 1);
        assert_eq!(paged[0].unit_price_sompi.as_deref(), Some("9"));

        let depth_rows = filter_listings_for_depth(asks, &query);
        let depth = ask_depth(&depth_rows, orderbook_depth_limit(&query));
        assert_eq!(
            depth
                .iter()
                .map(|row| row.unit_price_sompi.as_str())
                .collect::<Vec<_>>(),
            vec!["8", "9"]
        );
    }

    #[test]
    fn kcc20_owner_lookup_rejects_malformed_prefixed_string() {
        assert!(kcc20_owner_lookup("kaspatest:not-real").is_err());
    }

    #[test]
    fn kcc20_owner_identifier_lookup_accepts_pubkey_address() {
        let address = Address::new(Prefix::Testnet, Version::PubKey, &[2u8; 32]).to_string();
        assert_eq!(
            kcc20_owner_identifier_lookup(&address, "portfolio").unwrap(),
            "02".repeat(32)
        );
    }

    #[test]
    fn kcc20_owner_identifier_lookup_rejects_script_hash_address() {
        let address = Address::new(Prefix::Testnet, Version::ScriptHash, &[3u8; 32]).to_string();
        let err = kcc20_owner_identifier_lookup(&address, "portfolio").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    fn test_state(
        pool: Option<PgPool>,
        payment_policy: api_payments::ApiPaymentPolicyCatalog,
    ) -> AppState {
        test_state_with_rest(pool, payment_policy, None)
    }

    fn test_state_with_rest(
        pool: Option<PgPool>,
        payment_policy: api_payments::ApiPaymentPolicyCatalog,
        direct_payment_rest: Option<RestClient>,
    ) -> AppState {
        test_state_with_rest_and_sync_guard(
            pool,
            payment_policy,
            direct_payment_rest,
            ApiPaymentChannelSyncGuard::new(None, 60),
        )
    }

    fn test_state_with_rest_and_sync_guard(
        pool: Option<PgPool>,
        payment_policy: api_payments::ApiPaymentPolicyCatalog,
        direct_payment_rest: Option<RestClient>,
        channel_sync_guard: ApiPaymentChannelSyncGuard,
    ) -> AppState {
        AppState {
            inner: Arc::new(RwLock::new(EngineHolder::new())),
            persister: pool.map(|pool| Arc::new(PgPersister::new(pool))),
            history_pool: None,
            history_progress: Arc::new(Mutex::new(None)),
            source_observation: Arc::new(Mutex::new(None)),
            rest_publication: Arc::new(Mutex::new(None)),
            network_id: "testnet-10".to_string(),
            payment_policy: Arc::new(payment_policy),
            direct_payment_rest,
            payment_metrics: Arc::new(ApiPaymentRuntimeMetrics::default()),
            http_metrics: Arc::new(HttpRequestMetrics::default()),
            channel_sync_guard: Arc::new(channel_sync_guard),
        }
    }

    fn payment_policy_app(state: AppState) -> Router {
        let swagger = Router::<AppState>::from(
            SwaggerUi::new("/swagger-ui").external_url_unchecked("/openapi.json", openapi::spec()),
        );
        Router::new()
            .merge(swagger)
            .route("/swagger", get(swagger_redirect))
            .route("/docs", get(swagger_redirect))
            .route("/livez", get(livez))
            .route("/readyz", get(readyz))
            .route("/health", get(health))
            .route("/health/live", get(health_live))
            .route("/metrics", get(metrics))
            .route("/payments/pricing", get(payments_pricing))
            .route("/payments/metrics", get(payments_metrics))
            .route("/payments/debug", get(payments_debug_ui))
            .route("/payments/challenges", post(payments_challenge))
            .route("/payments/direct-proofs", post(payments_direct_proof))
            .route(
                "/payments/direct-proofs/{txid}",
                get(payments_direct_proof_status),
            )
            .route(
                "/payments/direct-proofs/{txid}/verify",
                post(payments_direct_proof_verify),
            )
            .route(
                "/payments/receipts/{receipt_id}",
                get(payments_receipt_status),
            )
            .route(
                "/payments/channels/{channel_id}",
                get(payments_channel_status),
            )
            .route(
                "/payments/channels/{channel_id}/sync",
                post(payments_channel_sync),
            )
            .route(
                "/payments/channels/{channel_id}/close",
                post(payments_channel_close),
            )
            .route(
                "/payments/settlements/{txid}",
                get(payments_settlement_status),
            )
            .route("/tx/{txid}/sync", post(tx_sync))
            .route("/tx/{txid}", get(events_by_txid))
            .route("/addresses/{address}/utxos", get(utxos_for_address))
            .route(
                "/addresses/{address}/kcc20/portfolio-assets",
                get(kcc20_portfolio_assets_for_address),
            )
            .route("/kcc20/discovery", get(kcc20_discovery))
            .route(
                "/kcc20/snapshot/controllers/{controller_id}/claims/{token_id}",
                get(kcc20_snapshot_claims),
            )
            .route(
                "/payments/proof/kcc20-discovery",
                get(payment_proof_kcc20_discovery),
            )
            .route("/fomo/rounds", get(fomo_rounds))
            .route("/fomo/rounds/{covenant_id}", get(fomo_round_detail))
            .route("/kcom/campaigns/{graph_id}", get(kcom_campaign))
            .route("/kcom/campaigns/{graph_id}/participants/{authority}", get(kcom_participant))
            .route("/kcc20/markets", get(kcc20_markets))
            .route("/payments/proof/body-echo", post(payment_proof_body_echo))
            .with_state(state)
    }

    #[tokio::test]
    async fn kcom_reads_reject_bad_ids_and_require_authenticated_database_state() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));
        let graph = "11".repeat(32);
        let authority = "22".repeat(32);
        for (path, expected) in [
            ("/kcom/campaigns/not-hex".to_owned(), StatusCode::BAD_REQUEST),
            (format!("/kcom/campaigns/{graph}"), StatusCode::SERVICE_UNAVAILABLE),
            (format!("/kcom/campaigns/{graph}/participants/not-hex"), StatusCode::BAD_REQUEST),
            (format!("/kcom/campaigns/{graph}/participants/{authority}"), StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let response = app.clone().oneshot(Request::builder().uri(path)
                .body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn snapshot_claim_route_validates_ids_and_requires_postgres() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));
        let malformed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/kcc20/snapshot/controllers/not-hex/claims/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        let unavailable = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/kcc20/snapshot/controllers/{}/claims/{}",
                        "11".repeat(32),
                        "22".repeat(32)
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    fn listing_row(
        status: &str,
        unit_price_sompi: &str,
        token_amount: &str,
        vout: i32,
    ) -> repo::Kcc20ListingRow {
        repo::Kcc20ListingRow {
            order_id: format!("{}:{}", "aa".repeat(32), vout),
            txid_hex: Some("aa".repeat(32)),
            vout: Some(vout),
            template_name: Some("KCC20Orderbook".to_string()),
            market_side: "ask".to_string(),
            sale_covenant_id_hex: "bb".repeat(32),
            sale_script_hash_hex: "cc".repeat(32),
            sale_address: "kaspatest:pqask".to_string(),
            token_id_hex: "dd".repeat(32),
            seller: Some("11".repeat(32)),
            token_amount: Some(token_amount.to_string()),
            price_sompi: None,
            unit_price_sompi: Some(unit_price_sompi.to_string()),
            min_fill_amount: None,
            fee_ticket_id: None,
            status: status.to_string(),
            close_txid_hex: None,
            close_entrypoint: None,
            sale_utxos: 1,
            locked_token_utxos: 1,
            locked_token_amount: Some(token_amount.to_string()),
            created_at_ms: i64::from(vout),
        }
    }

    fn bid_row(
        status: &str,
        unit_price_sompi: &str,
        token_amount: &str,
        vout: i32,
    ) -> repo::Kcc20BidRow {
        repo::Kcc20BidRow {
            order_id: format!("{}:{}", "ee".repeat(32), vout),
            txid_hex: Some("ee".repeat(32)),
            vout: Some(vout),
            template_name: Some("KCC20Orderbook".to_string()),
            market_side: "bid".to_string(),
            bid_covenant_id_hex: "ff".repeat(32),
            bid_script_hash_hex: "00".repeat(32),
            bid_address: "kaspatest:pqbid".to_string(),
            token_id_hex: "dd".repeat(32),
            buyer: Some("22".repeat(32)),
            token_amount: Some(token_amount.to_string()),
            price_sompi: None,
            unit_price_sompi: Some(unit_price_sompi.to_string()),
            min_fill_amount: None,
            fee_ticket_id: None,
            status: status.to_string(),
            close_txid_hex: None,
            close_entrypoint: None,
            bid_utxos: 1,
            bid_value_sompi: Some("1".to_string()),
            created_at_ms: i64::from(vout),
        }
    }

    fn direct_policy() -> api_payments::ApiPaymentPolicyCatalog {
        api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777)
            .with_direct_recipient(Some("kaspatest:qdirectrecipient".to_string()))
    }

    fn signing_keypair() -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[9u8; 32]).unwrap()
    }

    fn payment_authorization(voucher: &ApiPaymentVoucher) -> String {
        format!(
            "Payment {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(voucher).unwrap())
        )
    }

    fn direct_payment_authorization(txid_hex: &str) -> String {
        format!(
            "Payment {}",
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "method": "kaspa-direct",
                    "txidHex": txid_hex,
                    "payerIdentifier": "api-key-hash-1",
                }))
                .unwrap()
            )
        )
    }

    fn direct_payment_rest_tx(
        txid_hex: &str,
        challenge_id: &str,
        request_hash: &str,
        accepted: bool,
    ) -> RestTransaction {
        RestTransaction {
            transaction_id: txid_hex.to_string(),
            payload: Some(api_payments::direct_payment_payload_hex(
                challenge_id,
                request_hash,
            )),
            is_accepted: accepted,
            accepting_block_hash: accepted.then(|| "aa".repeat(32)),
            accepting_block_blue_score: accepted.then_some(123),
            accepting_block_time: accepted.then_some(1_780_000_030_000),
            outputs: vec![RestTxOutput {
                transaction_id: txid_hex.to_string(),
                index: 0,
                amount: 777,
                script_public_key: "00".to_string(),
                script_public_key_address: Some("kaspatest:qdirectrecipient".to_string()),
                script_public_key_type: Some("pubkey".to_string()),
                covenant_id: None,
                covenant: None,
            }],
            ..Default::default()
        }
    }

    fn signed_close_request(
        channel_id: &str,
        payer_pubkey: String,
        provider_pubkey: String,
    ) -> ApiPaymentChannelCloseRequest {
        let keypair = signing_keypair();
        let issued_at_ms = now_ms();
        let mut request = ApiPaymentChannelCloseRequest {
            schema: API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: channel_id.to_string(),
            payer_pubkey,
            provider_pubkey,
            requested_at_ms: issued_at_ms,
            expires_at_ms: issued_at_ms + 60_000,
            nonce: format!("close-{channel_id}-{issued_at_ms}"),
            reason: Some("wallet-close".to_string()),
            signature: String::new(),
        };
        let message = Message::from_digest(request.signing_digest());
        request.signature = hex::encode(
            secp256k1::SECP256K1
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        );
        request
    }

    fn assert_payment_response_redacted(value: &serde_json::Value) {
        let forbidden = [
            "authorization",
            "credential",
            "signature",
            "payerIdentifier",
            "payerPubkey",
            "providerPubkey",
            "rawStatusSnapshot",
        ];
        assert_payment_response_redacted_at(value, "$", &forbidden);
    }

    fn assert_payment_response_redacted_at(
        value: &serde_json::Value,
        path: &str,
        forbidden: &[&str],
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    assert!(
                        !forbidden
                            .iter()
                            .any(|field| key.eq_ignore_ascii_case(field)),
                        "sensitive payment field {key} leaked at {path}"
                    );
                    assert_payment_response_redacted_at(
                        nested,
                        &format!("{path}.{key}"),
                        forbidden,
                    );
                }
            }
            serde_json::Value::Array(items) => {
                for (index, nested) in items.iter().enumerate() {
                    assert_payment_response_redacted_at(
                        nested,
                        &format!("{path}[{index}]"),
                        forbidden,
                    );
                }
            }
            _ => {}
        }
    }

    fn payment_tracing_blocks(source: &str) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut blocks = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("tracing::") {
                continue;
            }
            let mut block = String::new();
            for next in &lines[idx..] {
                block.push_str(next);
                block.push('\n');
                if next.trim() == ");" {
                    break;
                }
            }
            if block.contains("target: \"api_payments\"")
                || block.contains("target: \"api_payment_settlement\"")
            {
                blocks.push(block);
            }
        }
        blocks
    }

    #[test]
    fn payment_structured_logs_use_allowlisted_fields() {
        let mut blocks = payment_tracing_blocks(include_str!("main.rs"));
        blocks.extend(payment_tracing_blocks(include_str!(
            "../../tn12-indexer-cli/src/main.rs"
        )));
        assert!(!blocks.is_empty(), "expected payment tracing blocks");

        let forbidden_field_markers = [
            "authorization =",
            "credential =",
            "credential_hash =",
            "signature =",
            "payer_identifier =",
            "payerIdentifier =",
            "payer_pubkey =",
            "payerPubkey =",
            "provider_pubkey =",
            "providerPubkey =",
            "provider_wallet",
            "private_key",
            "raw_status_snapshot",
            "rawStatusSnapshot",
        ];

        for block in blocks {
            for forbidden in forbidden_field_markers {
                assert!(
                    !block.contains(forbidden),
                    "sensitive payment log field marker `{forbidden}` found in:\n{block}"
                );
            }
        }
    }

    fn signed_discovery_voucher(uri: &str, sequence: u64, amount_sompi: u64) -> ApiPaymentVoucher {
        signed_payment_voucher(
            api_payments::get_request_hash(&uri.parse::<Uri>().unwrap()),
            api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
            api_payments::API_PAYMENT_PROOF_DISCOVERY_ROUTE,
            "discovery",
            sequence,
            amount_sompi,
        )
    }

    fn signed_payment_voucher(
        request_hash: String,
        pricing_id: &str,
        route: &str,
        nonce_prefix: &str,
        sequence: u64,
        amount_sompi: u64,
    ) -> ApiPaymentVoucher {
        let keypair = signing_keypair();
        let issued_at_ms = now_ms();
        let mut voucher = ApiPaymentVoucher {
            schema: API_PAYMENT_VOUCHER_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan-discovery".to_string(),
            payer_pubkey: hex::encode(keypair.x_only_public_key().0.serialize()),
            provider_pubkey: "cc".repeat(32),
            sequence,
            total_spent_sompi: amount_sompi,
            incremental_amount_sompi: amount_sompi,
            request_hash,
            pricing_id: pricing_id.to_string(),
            route: route.to_string(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + 60_000,
            nonce: format!("{nonce_prefix}-{sequence}"),
            signature: String::new(),
        };
        let message = Message::from_digest(voucher.signing_digest());
        voucher.signature = hex::encode(
            secp256k1::SECP256K1
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        );
        voucher
    }

    async fn insert_discovery_channel(pool: &PgPool) {
        let keypair = signing_keypair();
        insert_api_payment_channel(
            pool,
            NewApiPaymentChannel {
                channel_id: "chan-discovery".to_string(),
                network_id: "testnet-10".to_string(),
                payer_identifier: "api-key-hash-discovery".to_string(),
                payer_pubkey: hex::encode(keypair.x_only_public_key().0.serialize()),
                provider_pubkey: "cc".repeat(32),
                provider_identifier: Some("kaspacom-api".to_string()),
                scope: Some("indexer-api".to_string()),
                deposit_sompi: 104_000_000,
                reserve_sompi: 50_000_000,
                status: "usable".to_string(),
                open_txid_hex: Some("33".repeat(32)),
                refund_after_daa: Some(123_456),
                pricing_policy_id: Some("dev-indexer".to_string()),
                indexed_at_ms: Some(now_ms() as i64),
                now_ms: now_ms() as i64,
            },
        )
        .await
        .unwrap();
    }

    async fn insert_closeable_channel(pool: &PgPool, channel_id: &str) -> (String, String) {
        let keypair = signing_keypair();
        let payer_pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        let provider_pubkey = "cc".repeat(32);
        insert_api_payment_channel(
            pool,
            NewApiPaymentChannel {
                channel_id: channel_id.to_string(),
                network_id: "testnet-10".to_string(),
                payer_identifier: "api-key-hash-close".to_string(),
                payer_pubkey: payer_pubkey.clone(),
                provider_pubkey: provider_pubkey.clone(),
                provider_identifier: Some("kaspacom-api".to_string()),
                scope: Some("indexer-api".to_string()),
                deposit_sompi: 10_000,
                reserve_sompi: 1_000,
                status: "usable".to_string(),
                open_txid_hex: Some("33".repeat(32)),
                refund_after_daa: Some(123_456),
                pricing_policy_id: Some("dev-indexer".to_string()),
                indexed_at_ms: Some(now_ms() as i64),
                now_ms: now_ms() as i64,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE api_payment_channels SET spent_sompi = 2500, latest_sequence = 1 WHERE channel_id = $1",
        )
        .bind(channel_id)
        .execute(pool)
        .await
        .unwrap();
        (payer_pubkey, provider_pubkey)
    }

    async fn insert_indexed_payment_channel_lifecycle(pool: &PgPool) {
        upsert_indexed_api_payment_channel_open(
            pool,
            IndexedApiPaymentChannelOpen {
                channel_id: "44".repeat(32),
                network_id: "testnet-10".to_string(),
                payer_pubkey: "aa".repeat(32),
                provider_pubkey: "bb".repeat(32),
                provider_payout_pubkey: "cc".repeat(32),
                voucher_domain_hash: "dd".repeat(32),
                deposit_sompi: 100_000_000,
                reserve_sompi: 50_000_000,
                max_spend_sompi: 50_000_000,
                refund_after_ms: 1_780_001_200_000,
                close_after_ms: 0,
                open_txid_hex: "11".repeat(32),
                indexed_at_ms: 1_780_000_100_000,
            },
        )
        .await
        .unwrap();

        apply_indexed_api_payment_channel_settlement(
            pool,
            IndexedApiPaymentChannelSettlement {
                channel_id: "44".repeat(32),
                txid_hex: "22".repeat(32),
                settled_total_sompi: 50_000_000,
                provider_amount_sompi: 50_000_000,
                payer_refund_sompi: 46_000_000,
                indexed_at_ms: 1_780_000_200_000,
            },
        )
        .await
        .unwrap()
        .unwrap();
    }

    async fn insert_market_summary(pool: &PgPool) {
        sqlx::query(
            r#"
            INSERT INTO kcc20_market_summaries (
                token_id, best_ask_unit_price_sompi, best_bid_unit_price_sompi,
                spread_sompi, open_ask_count, open_bid_count,
                total_volume_sompi, total_trades, last_trade_txid,
                last_trade_time_ms, refreshed_at_ms, source_blue_score,
                volume_24h_sompi, volume_7d_sompi, trade_count_24h,
                trade_count_7d
            )
            VALUES (
                decode($1, 'hex'), 200, 150, 50, 1, 1, 1000, 2,
                decode($2, 'hex'), 12345, 12346, 999, 700, 900, 1, 2
            )
            "#,
        )
        .bind("44".repeat(32))
        .bind("55".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_health_cursor(pool: &PgPool, cursor_blue_score: i64, rest_blue_score: i64) {
        sqlx::query(
            r#"INSERT INTO indexer_state (key, value, updated_at_ms)
               VALUES (
                 'chain_realtime_tip_cursor',
                 $1,
                 EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
               )
               ON CONFLICT (key) DO UPDATE
               SET value = EXCLUDED.value,
                   updated_at_ms = EXCLUDED.updated_at_ms"#,
        )
        .bind(json!({
            "blue_score": cursor_blue_score,
            "rest_database_blue_score": rest_blue_score,
            "rest_database_observed_at_ms": now_ms() as i64
        }))
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_fomo_round(pool: &PgPool) -> String {
        let block = vec![0x71_u8; 32];
        let covenant_id = vec![0x72_u8; 32];
        let genesis_txid = vec![0x73_u8; 32];
        sqlx::query(
            r#"INSERT INTO blocks
               (hash, blue_score, daa_score, parent_hashes, timestamp_ms, is_chain_block, indexed_at_ms)
               VALUES ($1, 1, 1, ARRAY[]::BYTEA[], 1780870300000, TRUE, 1780870300000)"#,
        )
        .bind(&block)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO covenants
               (covenant_id, address, script_version, script_hash, template_name,
                genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
                classification_kind, classification_status)
               VALUES ($1, 'kaspatest:pfomoroute', 0, $1, 'KaspaFomoRound',
                       $2, 0, $3, 1780870300000, NULL, 'covenant', 'matched')"#,
        )
        .bind(&covenant_id)
        .bind(&genesis_txid)
        .bind(&block)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO covenant_utxos
               (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
                state, created_block, spent_block, spent_by_txid, status)
               VALUES ($1, 0, $2, 'kaspatest:pfomoroute', 2600000000, $3,
                       $4::JSONB, $5, NULL, NULL, 'active')"#,
        )
        .bind(vec![0x74_u8; 32])
        .bind(&covenant_id)
        .bind(vec![0u8; 35])
        .bind(json!({
            "lastBuyer": "cd".repeat(32),
            "endTimeMs": "1780870388002",
            "ticketCount": "3",
            "modeName": "activeRound"
        }))
        .bind(&block)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO covenant_actions
               (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
               VALUES ($1, $2, $3, 1780870310000, 'spend', 'buy', '{}'::JSONB, NULL, '{}'::JSONB)"#,
        )
        .bind(&covenant_id)
        .bind(vec![0x75_u8; 32])
        .bind(&block)
        .execute(pool)
        .await
        .unwrap();
        hex::encode(covenant_id)
    }

    #[tokio::test]
    async fn payments_pricing_reports_free_and_paid_routes() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 50_000_000),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payments/pricing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["networkId"], json!("testnet-10"));
        assert!(body["freeRoutes"]
            .as_array()
            .unwrap()
            .contains(&json!("GET /health")));
        assert_eq!(
            paid_route(&body, api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID)["amountSompi"],
            json!("50000000")
        );
        assert_eq!(
            paid_route(&body, api_payments::API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID)["route"],
            json!(api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE)
        );
        assert_eq!(
            paid_route(&body, api_payments::API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID)["amountSompi"],
            json!("50000000")
        );
    }

    fn paid_route<'a>(pricing: &'a serde_json::Value, pricing_id: &str) -> &'a serde_json::Value {
        pricing["paidRoutes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|route| route["pricingId"] == json!(pricing_id))
            .unwrap()
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn fomo_round_routes_return_indexed_state(pool: PgPool) {
        let covenant_id = insert_fomo_round(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/fomo/rounds?active=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-total-count"], "1");
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["covenantIdHex"], covenant_id);
        assert_eq!(body[0]["status"], "active");
        assert_eq!(body[0]["potSompi"], "2600000000");
        assert_eq!(body[0]["lastBuyer"], "cd".repeat(32));
        assert_eq!(body[0]["ticketCount"], "3");
        assert_eq!(body[0]["buyCount"], 1);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/fomo/rounds/{covenant_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["round"]["covenantIdHex"], covenant_id);
        assert_eq!(body["actions"].as_array().unwrap().len(), 1);
        assert_eq!(body["utxos"].as_array().unwrap().len(), 1);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/fomo/rounds/not-a-hex-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn address_utxo_route_returns_consistent_page_and_total(pool: PgPool) {
        insert_fomo_round(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/addresses/kaspatest:pfomoroute/utxos?limit=1&offset=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-total-count"], "1");
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["amountSompi"], 2_600_000_000_i64);
        assert_eq!(body[0]["amountSompiExact"], "2600000000");
    }

    #[test]
    fn api_payments_rollback_free_overrides_enabled_flag() {
        let cli = Cli::try_parse_from([
            "covenant-tools-api",
            "--api-payments-enabled",
            "--api-payments-rollback-free",
            "--api-payment-kcc20-discovery-sompi",
            "50000000",
        ])
        .unwrap();

        assert!(cli.api_payments_enabled);
        assert!(cli.api_payments_rollback_free);
        assert_eq!(cli.api_payment_kcc20_discovery_sompi, 50_000_000);
        assert!(!api_payments_enforced(&cli));
    }

    #[test]
    fn api_payment_paid_routes_flag_is_parsed() {
        let cli = Cli::try_parse_from([
            "covenant-tools-api",
            "--api-payment-paid-routes",
            "GET /payments/proof/kcc20-discovery",
        ])
        .unwrap();

        assert_eq!(
            cli.api_payment_paid_routes.as_deref(),
            Some("GET /payments/proof/kcc20-discovery")
        );
    }

    #[tokio::test]
    async fn payments_pricing_reports_rollback_switch_disabled_routes() {
        let cli = Cli::try_parse_from([
            "covenant-tools-api",
            "--api-payments-enabled",
            "--api-payments-rollback-free",
            "--api-payment-kcc20-discovery-sompi",
            "50000000",
        ])
        .unwrap();
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(
                api_payments_enforced(&cli),
                "testnet-10",
                cli.api_payment_kcc20_discovery_sompi,
            ),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payments/pricing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["enabled"], json!(false));
        assert_eq!(body["paidRoutes"][0]["amountSompi"], json!("50000000"));
        assert_eq!(body["paidRoutes"][0]["enabled"], json!(false));
    }

    #[tokio::test]
    async fn payments_challenge_returns_same_request_hash_as_runtime_route() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 50_000_000),
        ));
        let runtime_uri = "/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi";
        let expected_hash = api_payments::get_request_hash(&runtime_uri.parse::<Uri>().unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=5&sortBy=totalVolumeSompi"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_some());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["pricingId"],
            json!(api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID)
        );
        assert_eq!(body["amountSompi"], json!("50000000"));
        assert_eq!(body["requestHash"], json!(expected_hash));
        assert_eq!(
            body["challenge"]["request"]["requestHash"],
            json!(expected_hash)
        );
    }

    #[tokio::test]
    async fn payments_challenge_rejects_unpriced_route_when_policy_disabled() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=5"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_none());
    }

    #[tokio::test]
    async fn payments_challenge_rejects_unsupported_route() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 50_000_000),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/health"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_none());
    }

    #[tokio::test]
    async fn payments_challenge_returns_direct_payment_request_when_configured() {
        let app = payment_policy_app(test_state(None, direct_policy()));
        let runtime_uri = "/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi";
        let expected_hash = api_payments::get_request_hash(&runtime_uri.parse::<Uri>().unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=5&sortBy=totalVolumeSompi",
                            "paymentMethod": "kaspa-direct"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_some());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["challenge"]["method"], json!("kaspa-direct"));
        assert_eq!(body["challenge"]["intent"], json!("charge"));
        assert_eq!(body["requestHash"], json!(expected_hash));
        assert_eq!(
            body["challenge"]["request"]["requestHash"],
            json!(expected_hash)
        );
        assert_eq!(
            body["challenge"]["request"]["recipientAddress"],
            json!("kaspatest:qdirectrecipient")
        );
    }

    #[tokio::test]
    async fn payments_challenge_rejects_direct_payment_without_recipient() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "paymentMethod": "kaspa-direct"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn operational_routes_stay_free_when_payment_policy_is_enabled() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        for path in [
            "/livez",
            "/readyz",
            "/health",
            "/openapi.json",
            "/swagger-ui",
            "/payments/pricing",
            "/payments/metrics",
            "/payments/debug",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert!(
                response.status().is_success() || response.status().is_redirection(),
                "{path} should stay free and reachable, got {}",
                response.status()
            );
            assert!(
                response
                    .headers()
                    .get(api_payments::WWW_AUTHENTICATE)
                    .is_none(),
                "{path} should not emit a payment challenge"
            );
            assert!(
                response
                    .headers()
                    .get(api_payments::PAYMENT_RECEIPT)
                    .is_none(),
                "{path} should not emit a payment receipt"
            );
        }
    }

    #[test]
    fn rich_health_distinguishes_availability_from_short_tip_drift() {
        let scanner = |age_ms, rest_observation_fresh, lag_blocks| repo::ScannerHealth {
            cursor_key: Some("chain_realtime_tip_cursor".to_string()),
            cursor_blue_score: Some(100),
            rest_database_blue_score: Some(100 + lag_blocks),
            cursor_updated_at_ms: Some(1),
            cursor_age_ms: Some(age_ms),
            rest_observation_age_ms: Some(age_ms),
            rest_observation_fresh,
            live_acceptance_observed_at_ms: Some(1),
            live_acceptance_blue_score: Some(100),
            live_acceptance_age_ms: Some(age_ms),
            live_acceptance_fresh: age_ms <= 60_000,
            latest_block_blue_score: Some(100),
            latest_block_time_ms: Some(1),
            latest_block_indexed_at_ms: Some(1),
            latest_action_time_ms: Some(1),
            db_cursor_lag_blocks: Some(lag_blocks),
            rest_db_lag_blocks: Some(0),
        };

        assert!(scanner_is_healthy(&scanner(1_000, true, 0)));
        assert!(!scanner_is_healthy(&scanner(16_000, false, 0)));
        assert!(scanner_is_healthy(&scanner(0, true, 33)));
        assert!(!scanner_is_healthy(&scanner(1_000, true, 501)));
        assert!(!scanner_live_ingestion_healthy(
            &scanner(1_000, true, 501),
            Some(601)
        ));
        assert!(!scanner_live_ingestion_healthy(
            &scanner(16_000, false, 0),
            None
        ));
        assert!(scanner_live_ingestion_healthy(
            &scanner(1_000, true, 100),
            Some(200)
        ));
        assert!(!scanner_live_ingestion_healthy(
            &scanner(1_000, true, 101),
            Some(201)
        ));
        let mut quiet_acceptance = scanner(1_000, true, 0);
        quiet_acceptance.latest_block_blue_score = Some(228);
        assert!(scanner_live_ingestion_healthy(&quiet_acceptance, Some(238)));
        quiet_acceptance.live_acceptance_fresh = false;
        assert!(!scanner_live_ingestion_healthy(
            &quiet_acceptance,
            Some(238)
        ));
        let mut repaired = scanner(1_000, true, 0);
        repaired.cursor_blue_score = Some(160);
        assert!(scanner_live_ingestion_healthy(&repaired, Some(201)));
        repaired.cursor_age_ms = Some(SCANNER_HEALTH_MAX_CURSOR_AGE_MS + 1);
        assert!(!scanner_live_ingestion_healthy(&repaired, Some(201)));
        repaired.cursor_age_ms = Some(1_000);
        repaired.live_acceptance_fresh = false;
        assert!(!scanner_live_ingestion_healthy(&repaired, Some(201)));
        assert!(scanner_live_ingestion_healthy(
            &scanner(1_000, false, 0),
            Some(100)
        ));
        let mut stale_rest_database = scanner(1_000, true, 0);
        stale_rest_database.latest_block_blue_score = Some(6_500_100);
        stale_rest_database.rest_db_lag_blocks = Some(6_500_000);
        assert!(!scanner_is_healthy(&stale_rest_database));
        assert!(scanner_live_ingestion_healthy(
            &stale_rest_database,
            Some(100)
        ));
        stale_rest_database.latest_block_blue_score = Some(3_100);
        stale_rest_database.rest_db_lag_blocks = Some(3_000);
        assert!(scanner_is_healthy(&stale_rest_database));
        let mut stale_live = scanner(1_000, true, 0);
        stale_live.live_acceptance_age_ms = Some(60_001);
        stale_live.live_acceptance_fresh = false;
        assert!(!scanner_is_healthy(&stale_live));
        assert!(!scanner_live_ingestion_healthy(&stale_live, Some(100)));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn health_route_keeps_fresh_short_tip_drift_available(pool: PgPool) {
        insert_health_cursor(&pool, 100, 133).await;
        let app = payment_policy_app(test_state(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["scanner"]["dbCursorLagBlocks"], json!(33));

        insert_health_cursor(&pool, 100, 600).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        insert_health_cursor(&pool, 100, 601).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["scanner"]["dbCursorLagBlocks"], json!(501));
    }

    #[tokio::test]
    async fn publication_metrics_separate_current_blocks_from_stalled_transactions() {
        use tn12_indexer_crawl::source_observation::{
            RestDatabasePublication, RestPublicationObservation,
        };
        let state = test_state(None, direct_policy());
        *state.source_observation.lock().unwrap() = Some(NodeObservation {
            endpoint: "wss://node/testnet-10".into(),
            network: "testnet-10".into(),
            blue_score: 700,
            observed_at_ms: now_ms() as i64,
            synced: true,
        });
        *state.rest_publication.lock().unwrap() = Some(RestPublicationObservation {
            endpoint: "https://node/rest".into(),
            network: "testnet-10".into(),
            observed_at_ms: now_ms() as i64,
            database: RestDatabasePublication {
                blue_score: 700,
                is_synced: Some(true),
                accepted_tx_block_time: Some(now_ms() as i64 - 600_000),
                accepted_tx_block_time_diff: Some(600),
            },
        });
        let response = metrics(State(state.clone())).await;
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("tn10_indexer_primary_rest_block_lag_scores 0\n"));
        assert!(text.contains("tn10_indexer_primary_rest_transaction_publication_current 0\n"));
        assert!(text.contains("tn10_indexer_primary_rest_observation_fresh 1\n"));
        state
            .rest_publication
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .observed_at_ms -= 30_000;
        let response = metrics(State(state)).await;
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("tn10_indexer_primary_rest_observation_fresh 0\n"));
        assert!(!text.contains("tn10_indexer_primary_rest_block_lag_scores 0\n"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn retained_missing_window_invalidates_later_verification_checkpoint(pool: PgPool) {
        insert_health_cursor(&pool,700,700).await;
        let state=test_state_with_rest(Some(pool.clone()),api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",50_000_000),None);
        *state.source_observation.lock().unwrap()=Some(NodeObservation {
            endpoint:"wss://node/testnet-10".into(),network:"testnet-10".into(),blue_score:700,
            observed_at_ms:now_ms() as i64,synced:true,
        });
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('tn10_history_coverage_verified',$1,$2)")
            .bind(json!({"verified":true,"verifiedThroughBlueScore":700})).bind(now_ms() as i64).execute(&pool).await.unwrap();
        assert_eq!(history_coverage(&state).await.unwrap().status,"complete");
        let writer=tn12_indexer_db::PgPersister::for_genesis_repair(pool.clone());
        let job=writer.prepare_settled_repair("chain_realtime_tip_cursor",100,100).await.unwrap();
        assert!(writer.defer_missing_history("chain_realtime_tip_cursor","chain_realtime_tip_cursor",job.epoch,200,"missing-parent","http://source",&json!({"child":"retained"}),"404").await.unwrap());
        let coverage=history_coverage(&state).await.unwrap();
        assert_eq!(coverage.status,"incomplete");
        assert_eq!(coverage.verification_watermark_blue_score,Some(99));
        assert_eq!(coverage.historical_verification.as_ref().unwrap()["verifiedThroughBlueScore"],700);
        assert_eq!(coverage.unverified_history.as_ref().unwrap().pending_windows,1);
        assert!(coverage.unverified_ranges.as_ref().unwrap().iter().any(|range| range.from_blue_score==100 && range.through_blue_score==199 && range.reason=="missing_source_transaction"));
        let response=health_history(State(state.clone())).await;
        assert_eq!(response.status(),StatusCode::OK);
        let body=to_bytes(response.into_body(),32768).await.unwrap();
        let body:serde_json::Value=serde_json::from_slice(&body).unwrap();
        assert_eq!(body["coverage"]["status"],"incomplete");
        assert_eq!(body["coverage"]["unverifiedHistory"]["windows"][0]["missingTxid"],"missing-parent");
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn settled_recheck_stall_invalidates_coverage_even_with_a_current_verified_tip(pool: PgPool) {
        insert_health_cursor(&pool, 700, 700).await;
        let state = test_state_with_rest(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
            None,
        );
        assert!(state.history_pool.is_none());
        *state.source_observation.lock().unwrap() = Some(NodeObservation {
            endpoint: "wss://node/testnet-10".into(),
            network: "testnet-10".into(),
            blue_score: 700,
            observed_at_ms: now_ms() as i64,
            synced: true,
        });
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('tn10_history_coverage_verified',$1,$2)")
            .bind(json!({"verified":true,"verifiedThroughBlueScore":700}))
            .bind(now_ms() as i64).execute(&pool).await.unwrap();
        assert_eq!(history_coverage(&state).await.unwrap().status, "complete");
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('chain_realtime_tip_cursor:settled_recheck',$1,$2)")
            .bind(json!({"next_blue_score":100,"last_completed_blue_score":0}))
            .bind(now_ms() as i64 - 600_000).execute(&pool).await.unwrap();
        let coverage = history_coverage(&state).await.unwrap();
        assert_eq!(coverage.status, "incomplete");
        assert_eq!(coverage.replay_status, "settled_recheck_stalled");
        assert_eq!(coverage.gap_scores, Some(0));
        let response = health_history(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["coverage"]["settledRecheck"]["nextBlueScore"], 100);
        let response = metrics(State(state)).await;
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("tn10_indexer_settled_recheck_cursor_age_seconds 600"));
        assert!(text.contains("tn10_indexer_settled_recheck_next_blue_score 100\n"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn fresh_journal_blocks_live_health_without_paging_as_stalled_recovery(pool: PgPool) {
        insert_health_cursor(&pool, 700, 700).await;
        let mut state = test_state(Some(pool.clone()), direct_policy());
        state.history_pool = Some(pool.clone());
        let now = now_ms() as i64;
        *state.source_observation.lock().unwrap() = Some(NodeObservation {
            endpoint: "wss://node/testnet-10".into(),
            network: "testnet-10".into(),
            blue_score: 700,
            observed_at_ms: now,
            synced: true,
        });
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('tn10_history_coverage_verified',$1,$2), ('chain_wrpc_acceptance_heartbeat',$3,$2)")
            .bind(json!({"verified":true,"verifiedThroughBlueScore":700}))
            .bind(now)
            .bind(json!({"blue_score":700}))
            .execute(&pool).await.unwrap();
        assert_eq!(history_coverage(&state).await.unwrap().status, "complete");
        assert_eq!(health_live(State(state.clone())).await.status(), StatusCode::OK);

        let observed = now_ms() as i64;
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms,created_at_ms) VALUES ('live_write_intent:testnet-10:test','{}',$1,$1)")
            .bind(observed - 1).execute(&pool).await.unwrap();
        let recovery = recovery_health::read(&pool, "testnet-10", observed).await.unwrap();
        assert_eq!(recovery.oldest_pending_intent_age_ms, Some(1));
        assert!(!recovery.clear());
        assert_eq!(history_coverage(&state).await.unwrap().status, "incomplete");
        assert_eq!(health_live(State(state.clone())).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(health(State(state.clone())).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        let history = health_history(State(state.clone())).await;
        let body = to_bytes(history.into_body(), 32768).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["coverage"]["status"], "incomplete");
        let response = metrics(State(state.clone())).await;
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        let metrics_text = std::str::from_utf8(&body).unwrap();
        assert!(metrics_text.contains("tn10_indexer_recovery_clear 0\n"));
        assert!(metrics_text.contains("tn10_indexer_live_ok 0\n"));
        assert!(metrics_text.contains("tn10_indexer_live_operational_ok 1\n"));
        assert!(metrics_text.contains("tn10_indexer_health_ok 0\n"));

        sqlx::query("UPDATE indexer_state SET created_at_ms=$1 WHERE key='live_write_intent:testnet-10:test'")
            .bind(now_ms() as i64 - 2_001).execute(&pool).await.unwrap();
        assert_eq!(health_live(State(state.clone())).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = metrics(State(state.clone())).await;
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        let metrics = std::str::from_utf8(&body).unwrap();
        assert!(metrics.contains("tn10_indexer_live_ok 0\n"));
        assert!(metrics.contains("tn10_indexer_live_operational_ok 0\n"));

        sqlx::query("DELETE FROM indexer_state WHERE key='live_write_intent:testnet-10:test'")
            .execute(&pool).await.unwrap();
        assert_eq!(history_coverage(&state).await.unwrap().status, "complete");
        assert_eq!(health_live(State(state)).await.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn live_health_reports_fresh_watcher_during_repair_backlog(pool: PgPool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let rest_app = Router::new().route(
            "/info/health",
            get(|| async {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"database": {"blueScore": 100, "isSynced": false}})),
                )
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, rest_app).await.unwrap() });
        insert_health_cursor(&pool, 100, 700).await;
        sqlx::query(
            "INSERT INTO indexer_state (key, value, updated_at_ms) \
             VALUES ('chain_wrpc_acceptance_heartbeat', '{\"blue_score\":700}', \
                     EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let state = test_state_with_rest(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
            Some(RestClient::new(format!("http://{address}")).unwrap()),
        );
        let source_observation = state.source_observation.clone();
        *source_observation.lock().unwrap() = Some(NodeObservation {
            endpoint: "wss://node/testnet-10".into(),
            network: "testnet-10".into(),
            blue_score: 700,
            observed_at_ms: now_ms() as i64,
            synced: true,
        });
        let app = payment_policy_app(state);

        let live = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);
        let body = to_bytes(live.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["scanner"]["dbCursorLagBlocks"], json!(600));
        assert_eq!(body["scanner"]["restObservationFresh"], json!(true));

        let metrics = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics = to_bytes(metrics.into_body(), 32768).await.unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains("tn10_indexer_live_ok 1\n"));
        assert!(metrics.contains("tn10_indexer_health_ok 0\n"));

        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('live_recovery_state:testnet-10:test','{\"phase\":\"recovering\"}',10)").execute(&pool).await.unwrap();
        let recovering = app.clone().oneshot(Request::builder().uri("/health/live").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(recovering.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(recovering.into_body(),8192).await.unwrap();
        let body: serde_json::Value=serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reasons"],json!(["canonical_recovery_pending"]));
        sqlx::query("DELETE FROM indexer_state WHERE key='live_recovery_state:testnet-10:test'").execute(&pool).await.unwrap();

        let aggregate = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(aggregate.status(), StatusCode::SERVICE_UNAVAILABLE);

        sqlx::query(
            "UPDATE indexer_state SET value = '{\"blue_score\":100}'::jsonb \
             WHERE key = 'chain_wrpc_acceptance_heartbeat'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let lagged = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lagged.status(), StatusCode::SERVICE_UNAVAILABLE);

        sqlx::query(
            "UPDATE indexer_state SET value = '{\"blue_score\":700}'::jsonb \
             WHERE key = 'chain_wrpc_acceptance_heartbeat'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE indexer_state SET value = jsonb_set(\
             value, '{rest_database_observed_at_ms}', \
             to_jsonb(EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 120000)) \
             WHERE key = 'chain_realtime_tip_cursor'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let stale_repair = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_repair.status(), StatusCode::OK);

        server.abort();
        let _ = server.await;
        *source_observation.lock().unwrap() = None;
        let stale_source = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_source.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn health_route_detects_frozen_rest_tip_from_wrpc_progress(pool: PgPool) {
        insert_health_cursor(&pool, 99, 100).await;
        sqlx::query(
            "INSERT INTO indexer_state (key, value, updated_at_ms) \
             VALUES ('chain_wrpc_acceptance_heartbeat', '{\"blue_score\":6500100}', \
                     EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 50_000_000),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["scanner"]["restDbLagBlocks"], json!(6_500_000));
        assert_eq!(body["scanner"]["liveAcceptanceBlueScore"], json!(6_500_100));
    }

    #[tokio::test]
    async fn payments_debug_ui_renders_redacted_support_lookup_page() {
        let app = payment_policy_app(test_state(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payments/debug")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.starts_with("text/html"));

        let body = to_bytes(response.into_body(), 16_384).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("payment-debug-app"));
        assert!(body.contains("/payments/receipts/"));
        assert!(body.contains("/payments/channels/"));
        assert!(body.contains("/payments/settlements/"));
        assert!(body.contains("/payments/direct-proofs/"));
        assert!(!body.to_ascii_lowercase().contains("private key"));
        assert!(!body.contains("Authorization"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_metrics_count_paid_route_outcomes(pool: PgPool) {
        insert_market_summary(&pool).await;
        insert_discovery_channel(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));
        let uri = "/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi";

        let missing_payment = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing_payment.status(), StatusCode::PAYMENT_REQUIRED);

        let metrics = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/payments/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = to_bytes(metrics.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["authorizationFailures"], json!(1));
        assert_eq!(body["paidRequestsServed"], json!(0));

        let voucher = signed_discovery_voucher(uri, 1, 50_000_000);
        let paid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(api_payments::AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paid.status(), StatusCode::OK);

        let metrics = app
            .oneshot(
                Request::builder()
                    .uri("/payments/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = to_bytes(metrics.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["authorizationFailures"], json!(1));
        assert_eq!(body["paidRequestsServed"], json!(1));
        assert_eq!(body["receiptRecordFailures"], json!(0));
        assert_eq!(body["receiptEncodeFailures"], json!(0));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payment_proof_kcc20_discovery_direct_retry_verifies_txid_and_serves(pool: PgPool) {
        insert_market_summary(&pool).await;
        let txid = "66".repeat(32);

        let challenge_app = payment_policy_app(test_state(Some(pool.clone()), direct_policy()));
        let challenge_response = challenge_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=5&sortBy=totalVolumeSompi",
                            "paymentMethod": "kaspa-direct"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge_response.status(), StatusCode::CREATED);
        let challenge_body = to_bytes(challenge_response.into_body(), 4096)
            .await
            .unwrap();
        let challenge_body: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();
        let challenge_id = challenge_body["challenge"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let request_hash = challenge_body["requestHash"].as_str().unwrap().to_string();
        let rest_tx = direct_payment_rest_tx(&txid, &challenge_id, &request_hash, true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_txid = txid.clone();
        let rest_app = Router::new().route(
            "/transactions/{txid}",
            get(move |Path(path_txid): Path<String>| {
                let expected_txid = expected_txid.clone();
                let rest_tx = rest_tx.clone();
                async move {
                    if path_txid == expected_txid {
                        (StatusCode::OK, Json(rest_tx)).into_response()
                    } else {
                        direct_payment_problem(
                            StatusCode::NOT_FOUND,
                            "test-tx-not-found",
                            "Test Tx Not Found",
                            None,
                        )
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, rest_app).await.unwrap();
        });
        let rest = RestClient::new(format!("http://{addr}")).unwrap();
        let app = payment_policy_app(test_state_with_rest(
            Some(pool.clone()),
            direct_policy(),
            Some(rest),
        ));
        let uri = "/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi";

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(
                        api_payments::AUTHORIZATION,
                        direct_payment_authorization(&txid),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let receipt = api_payments::decode_payment_receipt_header(
            response
                .headers()
                .get(api_payments::PAYMENT_RECEIPT)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.receipt_id, format!("apd_{txid}"));
        assert_eq!(receipt.channel_id, None);
        assert_eq!(receipt.voucher_sequence, None);
        assert_eq!(receipt.amount_sompi, 777);
        assert_eq!(
            receipt.pricing_id,
            api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID
        );
        assert_eq!(receipt.request_hash, request_hash);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);

        let proof_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/direct-proofs/{txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proof_response.status(), StatusCode::OK);
        let proof_body = to_bytes(proof_response.into_body(), 4096).await.unwrap();
        let proof_body: serde_json::Value = serde_json::from_slice(&proof_body).unwrap();
        assert_payment_response_redacted(&proof_body);
        assert_eq!(proof_body["status"], json!("accepted"));
        assert_eq!(proof_body["receiptId"], json!(receipt.receipt_id));
        assert_eq!(proof_body["requestHash"], json!(request_hash));

        let persisted_payer_hash: Option<String> = sqlx::query_scalar(
            r#"
            SELECT encode(wallet_or_api_key_hash, 'hex')
            FROM api_payment_usage_events
            WHERE receipt_id = $1
            "#,
        )
        .bind(&receipt.receipt_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            persisted_payer_hash,
            Some(api_payments::payer_identifier_hash_hex("api-key-hash-1"))
        );
        server.abort();
    }

    #[tokio::test]
    async fn failed_http_logs_share_request_identity_and_route() {
        use std::io::Write;
        use tracing::instrument::WithSubscriber;

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(capture.clone())
            .finish();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let fail_together = move || {
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let app = Router::new()
            .route("/health", get(fail_together.clone()))
            .route("/tokens/{id}", get(fail_together))
            .layer(TraceLayer::new_for_http())
            .layer(middleware::from_fn_with_state(
                Arc::new(HttpRequestMetrics::default()),
                trace_slow_request,
            ));
        async {
            let health = app.clone().oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-request-id", "untrusted-client-id")
                    .body(Body::empty())
                    .unwrap(),
            );
            let tokens = app.oneshot(
                Request::builder()
                    .uri("/tokens/private-value?secret=query")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (health, tokens) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(health, tokens)
            })
            .await
            .expect("both request handlers must reach the barrier");
            assert_eq!(health.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(tokens.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        .with_subscriber(subscriber)
        .await;
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        let failures: Vec<_> = text
            .lines()
            .filter(|line| {
                line.contains("tower_http::trace::on_failure")
                    || line.contains("slow or failed HTTP request")
            })
            .collect();
        assert_eq!(failures.len(), 4, "{text}");
        let mut by_request = BTreeMap::<String, Vec<&str>>::new();
        for line in failures {
            let identity = line
                .split("request_id=")
                .nth(1)
                .expect("failure record must carry a server request identity")
                .split_whitespace()
                .next()
                .unwrap()
                .to_string();
            by_request.entry(identity).or_default().push(line);
        }
        assert_eq!(by_request.len(), 2, "{text}");
        for lines in by_request.values() {
            assert_eq!(lines.len(), 2, "{text}");
            assert!(lines
                .iter()
                .any(|line| line.contains("tower_http::trace::on_failure")));
            assert!(lines
                .iter()
                .any(|line| line.contains("slow or failed HTTP request")));
            let health = lines[0].contains("route=\"/health\"");
            for line in lines {
                assert!(line.contains("method=GET"), "{line}");
                assert_eq!(line.contains("route=\"/health\""), health, "{line}");
                assert_eq!(line.contains("route=\"/tokens/{id}\""), !health, "{line}");
            }
        }
        for sensitive in ["private-value", "secret=query", "untrusted-client-id"] {
            assert!(!text.contains(sensitive), "{text}");
        }
    }

    #[test]
    fn http_request_metrics_render_route_status_and_duration() {
        let metrics = HttpRequestMetrics::default();
        metrics.record(
            "POST",
            "/tx/{txid}/sync",
            StatusCode::SERVICE_UNAVAILABLE,
            2.5,
        );

        let rendered = metrics.render();
        assert!(rendered.contains(
            "tn10_indexer_http_requests_total{method=\"POST\",route=\"/tx/{txid}/sync\",status_class=\"5xx\"} 1"
        ));
        assert!(rendered.contains(
            "tn10_indexer_http_request_duration_seconds_bucket{method=\"POST\",route=\"/tx/{txid}/sync\",status_class=\"5xx\",le=\"2\"} 0"
        ));
        assert!(rendered.contains(
            "tn10_indexer_http_request_duration_seconds_bucket{method=\"POST\",route=\"/tx/{txid}/sync\",status_class=\"5xx\",le=\"5\"} 1"
        ));
    }

    #[tokio::test]
    async fn http_request_metrics_use_matched_route_templates() {
        let metrics = Arc::new(HttpRequestMetrics::default());
        let app = Router::new()
            .route(
                "/metric-test/{id}",
                get(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(middleware::from_fn_with_state(
                Arc::clone(&metrics),
                trace_slow_request,
            ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metric-test/high-cardinality-value")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let rendered = metrics.render();
        assert!(rendered.contains("route=\"/metric-test/{id}\""));
        assert!(!rendered.contains("high-cardinality-value"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn portfolio_assets_route_validates_readiness_and_returns_exact_envelope(pool: PgPool) {
        let app = payment_policy_app(test_state(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let malformed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/addresses/not-an-owner/kcc20/portfolio-assets?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        let owner = "21".repeat(32);
        let unavailable = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/addresses/{owner}/kcc20/portfolio-assets?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let dirty_id = repo::kcc20_projection_dirty_target_for(
            &pool,
            repo::kcc20_owner_portfolio_assets_projection_name(),
        )
        .await
        .unwrap()
        .unwrap();
        repo::refresh_kcc20_owner_portfolio_assets(&pool)
            .await
            .unwrap();
        repo::mark_kcc20_projection_refreshed_for(
            &pool,
            repo::kcc20_owner_portfolio_assets_projection_name(),
            dirty_id,
        )
        .await
        .unwrap();
        for tag in [0x31_u8, 0x32] {
            sqlx::query(
                r#"INSERT INTO kcc20_owner_portfolio_assets
                   (owner_identifier, canonical_token_id, native_balance, total_balance,
                    asset_utxo_count, refreshed_at_ms)
                   VALUES ($1, $2, $3, $3, 1, 1000)"#,
            )
            .bind(vec![0x21_u8; 32])
            .bind(vec![tag; 32])
            .bind(i64::from(tag))
            .execute(&pool)
            .await
            .unwrap();
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/addresses/{owner}/kcc20/portfolio-assets?limit=1&offset=1&sortBy=nativeBalance&sortDirection=desc"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["total"], json!(2));
        assert_eq!(body["limit"], json!(1));
        assert_eq!(body["offset"], json!(1));
        assert_eq!(body["sortBy"], json!("nativeBalance"));
        assert_eq!(body["sortDirection"], json!("desc"));
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            body["items"][0]["canonicalTokenIdHex"],
            json!("31".repeat(32))
        );

        let filtered = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/addresses/{owner}/kcc20/portfolio-assets?search=32&tokenId={}&hasNativeBalance=true&hasOrderbookBalance=false&hasOpenOrders=false",
                        "32".repeat(32)
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(filtered.status(), StatusCode::OK);
        let body = to_bytes(filtered.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["total"], json!(1));
        assert_eq!(
            body["items"][0]["canonicalTokenIdHex"],
            json!("32".repeat(32))
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_discovery_stays_free_when_payment_policy_is_disabled(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/discovery?limit=5&sortBy=totalVolumeSompi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_discovery_stays_free_when_rollback_switch_is_enabled(pool: PgPool) {
        insert_market_summary(&pool).await;
        let cli = Cli::try_parse_from([
            "covenant-tools-api",
            "--api-payments-enabled",
            "--api-payments-rollback-free",
            "--api-payment-kcc20-discovery-sompi",
            "777",
        ])
        .unwrap();
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(
                api_payments_enforced(&cli),
                "testnet-10",
                cli.api_payment_kcc20_discovery_sompi,
            ),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/discovery?limit=5&sortBy=totalVolumeSompi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_discovery_stays_free_when_paid_route_allowlist_is_empty(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777)
                .with_paid_route_allowlist(Some("")),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/discovery?limit=5&sortBy=totalVolumeSompi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_discovery_stays_free_when_payment_policy_is_enabled(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/discovery?limit=5&sortBy=totalVolumeSompi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_none());
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_markets_uses_summary_table_fast_path(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/markets?limit=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-total-count")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = body.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["tokenIdHex"], json!("44".repeat(32)));
        assert_eq!(items[0]["bestAskUnitPriceSompi"], json!("200"));
        assert_eq!(items[0]["bestBidUnitPriceSompi"], json!("150"));
        assert_eq!(items[0]["spreadSompi"], json!("50"));
        assert_eq!(items[0]["openAskCount"], json!(1));
        assert_eq!(items[0]["openBidCount"], json!(1));
        assert_eq!(items[0]["totalVolumeSompi"], json!("1000"));
        assert_eq!(items[0]["totalTrades"], json!(2));
        assert_eq!(items[0]["lastTradeTxidHex"], json!("55".repeat(32)));
        assert_eq!(items[0]["lastTradeTimeMs"], json!(12345));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn kcc20_markets_without_limit_is_bounded(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kcc20/markets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-total-count")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = body.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["tokenIdHex"], json!("44".repeat(32)));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payment_proof_kcc20_discovery_requires_payment_when_policy_is_enabled(pool: PgPool) {
        insert_market_summary(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_some());
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("missing-payment"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payment_proof_kcc20_discovery_paid_retry_returns_receipt_and_items(pool: PgPool) {
        insert_market_summary(&pool).await;
        insert_discovery_channel(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));
        let uri = "/payments/proof/kcc20-discovery?limit=5&sortBy=totalVolumeSompi";
        let voucher = signed_discovery_voucher(uri, 1, 50_000_000);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(api_payments::AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let receipt = api_payments::decode_payment_receipt_header(
            response
                .headers()
                .get(api_payments::PAYMENT_RECEIPT)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.channel_id.as_deref(), Some("chan-discovery"));
        assert_eq!(receipt.voucher_sequence, Some(1));
        assert_eq!(receipt.amount_sompi, 50_000_000);
        assert_eq!(
            receipt.pricing_id,
            api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID
        );

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);

        let receipt_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/receipts/{}", receipt.receipt_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_body = to_bytes(receipt_response.into_body(), 8192).await.unwrap();
        let receipt_body: serde_json::Value = serde_json::from_slice(&receipt_body).unwrap();
        assert_payment_response_redacted(&receipt_body);
        assert_eq!(receipt_body["receiptId"], json!(receipt.receipt_id));
        assert_eq!(receipt_body["channelId"], json!("chan-discovery"));
        assert_eq!(
            receipt_body["route"],
            json!(api_payments::API_PAYMENT_PROOF_DISCOVERY_ROUTE)
        );
        assert_eq!(
            receipt_body["pricingId"],
            json!(api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID)
        );
        assert_eq!(receipt_body["amountSompi"], json!("50000000"));
        assert_eq!(receipt_body["voucherSequence"], json!("1"));
        assert_eq!(receipt_body["responseStatus"], json!(200));
        assert_eq!(receipt_body["requestHash"], json!(receipt.request_hash));
        assert_eq!(receipt_body["voucherTotalSpentSompi"], json!("50000000"));
        assert_eq!(receipt_body["channelStatus"], json!("usable"));
        let persisted_payer_hash: Option<String> = sqlx::query_scalar(
            r#"
            SELECT encode(wallet_or_api_key_hash, 'hex')
            FROM api_payment_usage_events
            WHERE receipt_id = $1
            "#,
        )
        .bind(&receipt.receipt_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let expected_payer_hash = api_payments::payer_identifier_hash_hex("api-key-hash-discovery");
        assert_eq!(
            persisted_payer_hash.as_deref(),
            Some(expected_payer_hash.as_str())
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payment_proof_body_echo_requires_payment_when_policy_is_enabled(pool: PgPool) {
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/proof/body-echo?case=missing")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"probe":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(api_payments::WWW_AUTHENTICATE)
            .is_some());
        assert!(response
            .headers()
            .get(api_payments::PAYMENT_RECEIPT)
            .is_none());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("missing-payment"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payment_proof_body_echo_paid_retry_binds_body_hash_and_returns_receipt(pool: PgPool) {
        insert_discovery_channel(&pool).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(true, "testnet-10", 777),
        ));
        let body_text = r#"{"probe":true,"route":"body-echo"}"#;
        let body_hash_hex = hex::encode(blake2b_256(body_text.as_bytes()));
        let uri = "/payments/proof/body-echo?case=paid";
        let request_hash = api_payments::get_request_hash_for_method(
            "POST",
            "/payments/proof/body-echo",
            Some("case=paid"),
            &body_hash_hex,
        );
        let voucher = signed_payment_voucher(
            request_hash.clone(),
            api_payments::API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID,
            api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
            "body-echo",
            1,
            50_000_000,
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header(api_payments::AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::from(body_text))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let receipt = api_payments::decode_payment_receipt_header(
            response
                .headers()
                .get(api_payments::PAYMENT_RECEIPT)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.channel_id.as_deref(), Some("chan-discovery"));
        assert_eq!(receipt.voucher_sequence, Some(1));
        assert_eq!(receipt.amount_sompi, 50_000_000);
        assert_eq!(
            receipt.pricing_id,
            api_payments::API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID
        );
        assert_eq!(receipt.request_hash, request_hash);

        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["route"],
            json!(api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE)
        );
        assert_eq!(body["bodyHashHex"], json!(body_hash_hex));
        assert_eq!(body["bodyByteLength"], json!(body_text.len()));
        assert_payment_response_redacted(&body);

        let receipt_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/receipts/{}", receipt.receipt_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_body = to_bytes(receipt_response.into_body(), 8192).await.unwrap();
        let receipt_body: serde_json::Value = serde_json::from_slice(&receipt_body).unwrap();
        assert_payment_response_redacted(&receipt_body);
        assert_eq!(
            receipt_body["route"],
            json!(api_payments::API_PAYMENT_PROOF_BODY_ECHO_ROUTE)
        );
        assert_eq!(
            receipt_body["pricingId"],
            json!(api_payments::API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID)
        );
        assert_eq!(receipt_body["requestHash"], json!(request_hash));
        assert_eq!(receipt_body["responseStatus"], json!(200));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_direct_proof_submit_and_status_are_replay_safe(pool: PgPool) {
        let app = payment_policy_app(test_state(Some(pool), direct_policy()));

        let challenge_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=5",
                            "paymentMethod": "kaspa-direct"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge_response.status(), StatusCode::CREATED);
        let challenge_body = to_bytes(challenge_response.into_body(), 4096)
            .await
            .unwrap();
        let challenge_body: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();
        let txid = "66".repeat(32);

        let proof = json!({
            "challengeId": challenge_body["challenge"]["id"],
            "networkId": "testnet-10",
            "txidHex": txid,
            "payerIdentifier": "api-key-hash-1",
            "recipientAddress": "kaspatest:qdirectrecipient",
            "amountSompi": "777",
            "pricingId": api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
            "route": api_payments::API_PAYMENT_PROOF_DISCOVERY_ROUTE,
            "requestHash": challenge_body["requestHash"]
        });

        let submit_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/direct-proofs")
                    .header("content-type", "application/json")
                    .body(Body::from(proof.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(submit_response.status(), StatusCode::ACCEPTED);
        let submit_body = to_bytes(submit_response.into_body(), 4096).await.unwrap();
        let submit_body: serde_json::Value = serde_json::from_slice(&submit_body).unwrap();
        assert_payment_response_redacted(&submit_body);
        assert_eq!(submit_body["status"], json!("submitted"));
        assert_eq!(submit_body["txidHex"], json!(txid));
        let direct_receipt_id = format!("apd_{txid}");
        assert_eq!(submit_body["receiptId"], json!(direct_receipt_id));

        let replay_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/direct-proofs")
                    .header("content-type", "application/json")
                    .body(Body::from(proof.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay_response.status(), StatusCode::CONFLICT);
        let replay_body = to_bytes(replay_response.into_body(), 4096).await.unwrap();
        let replay_body: serde_json::Value = serde_json::from_slice(&replay_body).unwrap();
        assert_eq!(
            replay_body["failureCode"],
            json!("payment-direct-proof-replay")
        );

        let mut same_challenge_different_txid = proof.clone();
        same_challenge_different_txid["txidHex"] = json!("67".repeat(32));
        let same_challenge_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/direct-proofs")
                    .header("content-type", "application/json")
                    .body(Body::from(same_challenge_different_txid.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(same_challenge_response.status(), StatusCode::CONFLICT);
        let same_challenge_body = to_bytes(same_challenge_response.into_body(), 4096)
            .await
            .unwrap();
        let same_challenge_body: serde_json::Value =
            serde_json::from_slice(&same_challenge_body).unwrap();
        assert_eq!(
            same_challenge_body["failureCode"],
            json!("payment-direct-proof-replay")
        );

        let second_challenge_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "method": "GET",
                            "path": "/payments/proof/kcc20-discovery",
                            "rawQuery": "limit=6",
                            "paymentMethod": "kaspa-direct"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_challenge_response.status(), StatusCode::CREATED);
        let second_challenge_body = to_bytes(second_challenge_response.into_body(), 4096)
            .await
            .unwrap();
        let second_challenge_body: serde_json::Value =
            serde_json::from_slice(&second_challenge_body).unwrap();
        let same_txid_different_challenge = json!({
            "challengeId": second_challenge_body["challenge"]["id"],
            "networkId": "testnet-10",
            "txidHex": txid,
            "payerIdentifier": "api-key-hash-1",
            "recipientAddress": "kaspatest:qdirectrecipient",
            "amountSompi": "777",
            "pricingId": api_payments::API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
            "route": api_payments::API_PAYMENT_PROOF_DISCOVERY_ROUTE,
            "requestHash": second_challenge_body["requestHash"]
        });
        let same_txid_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payments/direct-proofs")
                    .header("content-type", "application/json")
                    .body(Body::from(same_txid_different_challenge.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(same_txid_response.status(), StatusCode::CONFLICT);
        let same_txid_body = to_bytes(same_txid_response.into_body(), 4096)
            .await
            .unwrap();
        let same_txid_body: serde_json::Value = serde_json::from_slice(&same_txid_body).unwrap();
        assert_eq!(
            same_txid_body["failureCode"],
            json!("payment-direct-proof-replay")
        );

        let status_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/direct-proofs/{txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status_response.status(), StatusCode::OK);
        let status_body = to_bytes(status_response.into_body(), 4096).await.unwrap();
        let status_body: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
        assert_payment_response_redacted(&status_body);
        assert_eq!(status_body["receiptId"], submit_body["receiptId"]);
        assert_eq!(status_body["status"], json!("submitted"));

        let receipt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/receipts/{direct_receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_body = to_bytes(receipt_response.into_body(), 4096).await.unwrap();
        let receipt_body: serde_json::Value = serde_json::from_slice(&receipt_body).unwrap();
        assert_payment_response_redacted(&receipt_body);
        assert_eq!(receipt_body, status_body);

        let verify_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/direct-proofs/{txid}/verify"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let verify_body = to_bytes(verify_response.into_body(), 4096).await.unwrap();
        let verify_body: serde_json::Value = serde_json::from_slice(&verify_body).unwrap();
        assert_eq!(
            verify_body["failureCode"],
            json!("payment-direct-verifier-unavailable")
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_channel_status_returns_projected_lifecycle(pool: PgPool) {
        insert_indexed_payment_channel_lifecycle(&pool).await;
        let channel_id = "44".repeat(32);
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/channels/{channel_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["channelId"], json!(channel_id));
        assert_eq!(body["status"], json!("settled"));
        assert_eq!(body["networkId"], json!("testnet-10"));
        assert_eq!(body["depositSompi"], json!("100000000"));
        assert_eq!(body["reserveSompi"], json!("50000000"));
        assert_eq!(body["spentSompi"], json!("50000000"));
        assert_eq!(body["remainingSompi"], json!("50000000"));
        assert_eq!(body["maxSpendSompi"], json!("50000000"));
        assert_eq!(body["refundAfterMs"], json!("1780001200000"));
        assert_eq!(body["openTxid"], json!("11".repeat(32)));
        assert_eq!(body["settlementTxid"], json!("22".repeat(32)));
        assert_eq!(body["providerPayoutPubkey"], json!("cc".repeat(32)));
        assert_eq!(body["voucherDomainHash"], json!("dd".repeat(32)));
        assert!(body["scanner"].is_object());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_channel_sync_fast_ingests_open_tx(pool: PgPool) {
        let raw =
            include_str!("../../../fixtures/api-payment-channel-tn10/01-settlement-open.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
        let txid = "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0";
        let channel_id = "af3c1065efa87396d1cefe1bf41a877370e5ce04878e3c18ef1cddcc8ba571c0";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_txid = txid.to_string();
        let rest_app = Router::new().route(
            "/transactions/{txid}",
            get(move |Path(path_txid): Path<String>| {
                let fixture = fixture.clone();
                let expected_txid = expected_txid.clone();
                async move {
                    if path_txid == expected_txid {
                        (StatusCode::OK, Json(fixture)).into_response()
                    } else {
                        direct_payment_problem(
                            StatusCode::NOT_FOUND,
                            "test-tx-not-found",
                            "Test Tx Not Found",
                            None,
                        )
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, rest_app).await.unwrap();
        });
        let rest = RestClient::new(format!("http://{addr}")).unwrap();
        let app = payment_policy_app(test_state_with_rest(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        ));

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/channels/{channel_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/sync"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "txidHex": txid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["channelId"], json!(channel_id));
        assert_eq!(body["status"], json!("usable"));
        assert_eq!(body["openTxid"], json!(txid));
        assert_eq!(body["depositSompi"], json!("100000000"));

        let projected = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/channels/{channel_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(projected.status(), StatusCode::OK);
        server.abort();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn tx_sync_fast_ingests_indexed_actions(pool: PgPool) {
        let raw =
            include_str!("../../../fixtures/api-payment-channel-tn10/01-settlement-open.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
        let txid = "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_txid = txid.to_string();
        let rest_hits = Arc::new(AtomicUsize::new(0));
        let rest_hits_for_app = Arc::clone(&rest_hits);
        let rest_app = Router::new().route(
            "/transactions/{txid}",
            get(move |Path(path_txid): Path<String>| {
                let fixture = fixture.clone();
                let expected_txid = expected_txid.clone();
                let rest_hits = Arc::clone(&rest_hits_for_app);
                async move {
                    if path_txid == expected_txid {
                        rest_hits.fetch_add(1, Ordering::Relaxed);
                        (StatusCode::OK, Json(fixture)).into_response()
                    } else {
                        direct_payment_problem(
                            StatusCode::NOT_FOUND,
                            "test-tx-not-found",
                            "Test Tx Not Found",
                            None,
                        )
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, rest_app).await.unwrap();
        });
        let rest = RestClient::new(format!("http://{addr}")).unwrap();
        let app = payment_policy_app(test_state_with_rest(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        ));

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::OK);
        let missing_body = to_bytes(missing.into_body(), 8192).await.unwrap();
        let missing_body: serde_json::Value = serde_json::from_slice(&missing_body).unwrap();
        assert_eq!(missing_body, json!([]));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{txid}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["txidHex"], json!(txid));
        assert_eq!(body["indexed"], json!(true));
        assert_eq!(body["actionCount"], json!(1));
        assert_eq!(body["persistStats"]["actionsInserted"], json!(1));
        assert_eq!(rest_hits.load(Ordering::Relaxed), 1);

        let cached = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{txid}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached.status(), StatusCode::OK);
        let cached_body = to_bytes(cached.into_body(), 8192).await.unwrap();
        let cached_body: serde_json::Value = serde_json::from_slice(&cached_body).unwrap();
        assert_eq!(cached_body["txidHex"], json!(txid));
        assert_eq!(cached_body["indexed"], json!(true));
        assert_eq!(cached_body["actionCount"], json!(1));
        assert_eq!(cached_body["persistStats"]["actionsInserted"], json!(0));
        assert_eq!(cached_body["scanner"], json!(null));
        assert_eq!(rest_hits.load(Ordering::Relaxed), 1);

        let forced = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{txid}/sync?force=true"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forced.status(), StatusCode::OK);
        let forced_body = to_bytes(forced.into_body(), 8192).await.unwrap();
        let forced_body: serde_json::Value = serde_json::from_slice(&forced_body).unwrap();
        assert_eq!(forced_body["txidHex"], json!(txid));
        assert_eq!(forced_body["indexed"], json!(true));
        assert_eq!(forced_body["actionCount"], json!(1));
        assert_eq!(forced_body["persistStats"]["actionsInserted"], json!(0));
        assert_eq!(rest_hits.load(Ordering::Relaxed), 2);

        let projected = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(projected.status(), StatusCode::OK);
        let projected_body = to_bytes(projected.into_body(), 8192).await.unwrap();
        let projected_body: serde_json::Value = serde_json::from_slice(&projected_body).unwrap();
        assert_eq!(projected_body.as_array().unwrap().len(), 1);
        server.abort();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn tx_sync_uses_fallback_rest_when_primary_misses_tx(pool: PgPool) {
        let raw =
            include_str!("../../../fixtures/api-payment-channel-tn10/01-settlement-open.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
        let txid = "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0";

        let primary_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        let primary_hits = Arc::new(AtomicUsize::new(0));
        let primary_hits_for_app = Arc::clone(&primary_hits);
        let primary_app = Router::new().route(
            "/transactions/{txid}",
            get(move |Path(_path_txid): Path<String>| {
                let primary_hits = Arc::clone(&primary_hits_for_app);
                async move {
                    primary_hits.fetch_add(1, Ordering::Relaxed);
                    direct_payment_problem(
                        StatusCode::NOT_FOUND,
                        "test-primary-tx-not-found",
                        "Test Primary Tx Not Found",
                        None,
                    )
                }
            }),
        );
        let primary_server = tokio::spawn(async move {
            axum::serve(primary_listener, primary_app).await.unwrap();
        });

        let fallback_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_listener.local_addr().unwrap();
        let expected_txid = txid.to_string();
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits_for_app = Arc::clone(&fallback_hits);
        let fallback_app = Router::new().route(
            "/transactions/{txid}",
            get(move |Path(path_txid): Path<String>| {
                let fixture = fixture.clone();
                let expected_txid = expected_txid.clone();
                let fallback_hits = Arc::clone(&fallback_hits_for_app);
                async move {
                    fallback_hits.fetch_add(1, Ordering::Relaxed);
                    if path_txid == expected_txid {
                        (StatusCode::OK, Json(fixture)).into_response()
                    } else {
                        direct_payment_problem(
                            StatusCode::NOT_FOUND,
                            "test-fallback-tx-not-found",
                            "Test Fallback Tx Not Found",
                            None,
                        )
                    }
                }
            }),
        );
        let fallback_server = tokio::spawn(async move {
            axum::serve(fallback_listener, fallback_app).await.unwrap();
        });

        let rest = RestClient::new(format!("http://{primary_addr}"))
            .unwrap()
            .with_fallback_urls([format!("http://{fallback_addr}")]);
        let app = payment_policy_app(test_state_with_rest(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{txid}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["txidHex"], json!(txid));
        assert_eq!(body["indexed"], json!(true));
        assert_eq!(body["actionCount"], json!(1));
        assert_eq!(primary_hits.load(Ordering::Relaxed), 1);
        assert_eq!(fallback_hits.load(Ordering::Relaxed), 1);

        primary_server.abort();
        fallback_server.abort();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn tx_sync_returns_accepted_when_transaction_has_not_propagated(pool: PgPool) {
        let txid = "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rest_app = Router::new().route(
            "/transactions/{txid}",
            get(|| async {
                direct_payment_problem(
                    StatusCode::NOT_FOUND,
                    "test-tx-not-found",
                    "Test Tx Not Found",
                    None,
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, rest_app).await.unwrap();
        });
        let rest = RestClient::new(format!("http://{addr}"))
            .unwrap()
            .with_fallback_urls(Vec::new());
        let app = payment_policy_app(test_state_with_rest(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{txid}/sync"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).unwrap(),
            HeaderValue::from_static("2")
        );
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["txidHex"], json!(txid));
        assert_eq!(body["indexed"], json!(false));
        assert_eq!(body["pending"], json!(true));
        assert_eq!(body["reason"], json!("transaction_not_found_yet"));
        assert_eq!(body["retryAfterMs"], json!(2_000));
        assert_eq!(body["actionCount"], json!(0));

        server.abort();
    }

    #[tokio::test]
    async fn payments_channel_sync_requires_configured_token() {
        let channel_id = "af".repeat(32);
        let txid = "e6".repeat(32);
        let app = payment_policy_app(test_state_with_rest_and_sync_guard(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            None,
            ApiPaymentChannelSyncGuard::new(Some("sync-fixture-value".to_string()), 60),
        ));

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/sync"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "txidHex": txid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let unauthorized_body = to_bytes(unauthorized.into_body(), 4096).await.unwrap();
        let unauthorized_body: serde_json::Value =
            serde_json::from_slice(&unauthorized_body).unwrap();
        assert_eq!(
            unauthorized_body["failureCode"],
            json!("payment-channel-sync-unauthorized")
        );

        let authorized = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/sync"))
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer sync-fixture-value")
                    .body(Body::from(json!({ "txidHex": txid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn payments_channel_sync_rate_limits_before_rest_lookup() {
        let channel_id = "af".repeat(32);
        let txid = "e6".repeat(32);
        let app = payment_policy_app(test_state_with_rest_and_sync_guard(
            None,
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            None,
            ApiPaymentChannelSyncGuard::new(None, 1),
        ));

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/sync"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "txidHex": txid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/sync"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "txidHex": txid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(second.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["failureCode"],
            json!("payment-channel-sync-rate-limited")
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_channel_close_requires_signed_payer_request(pool: PgPool) {
        let channel_id = "55".repeat(32);
        let (payer_pubkey, provider_pubkey) = insert_closeable_channel(&pool, &channel_id).await;
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));
        let close_request = signed_close_request(&channel_id, payer_pubkey, provider_pubkey);
        let mut tampered = close_request.clone();
        tampered.reason = Some("tampered-after-signing".to_string());

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/close"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&tampered).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let rejected_body = to_bytes(rejected.into_body(), 4096).await.unwrap();
        let rejected_body: serde_json::Value = serde_json::from_slice(&rejected_body).unwrap();
        assert_eq!(
            rejected_body["failureCode"],
            json!("payment-close-signature-invalid")
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/payments/channels/{channel_id}/close"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&close_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["channelId"], json!(channel_id));
        assert_eq!(body["status"], json!("close_requested"));
        assert_eq!(body["spentSompi"], json!("2500"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_settlement_status_returns_indexed_settlement(pool: PgPool) {
        insert_indexed_payment_channel_lifecycle(&pool).await;
        let channel_id = "44".repeat(32);
        let settlement_txid = "22".repeat(32);
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/settlements/{settlement_txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["txidHex"], json!(settlement_txid));
        assert_eq!(body["indexed"], json!(true));
        assert_eq!(body["kind"], json!("settlement"));
        assert_eq!(body["channelId"], json!(channel_id));
        assert_eq!(body["channelStatus"], json!("settled"));
        assert_eq!(body["settledTotalSompi"], json!("50000000"));
        assert_eq!(body["providerAmountSompi"], json!("50000000"));
        assert_eq!(body["payerRefundSompi"], json!("46000000"));
        assert_eq!(body["indexerStatus"], json!("indexed"));
        assert!(body["scanner"].is_object());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn payments_settlement_status_returns_unindexed_for_unknown_tx(pool: PgPool) {
        let unknown_txid = "99".repeat(32);
        let app = payment_policy_app(test_state(
            Some(pool),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payments/settlements/{unknown_txid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["txidHex"], json!(unknown_txid));
        assert_eq!(body["indexed"], json!(false));
        assert!(body["kind"].is_null());
        assert!(body["scanner"].is_object());
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn deferred_decode_is_visible_on_cached_sync_raw_reads_and_history(pool: PgPool) {
        let txid = "11".repeat(32);
        sqlx::query("INSERT INTO indexer_deferred_decodes(txid,block_hash,blue_score,covenant_ids,raw_transaction,reason,status) VALUES($1,$2,1,ARRAY[$1]::bytea[],'{}','unsupported_test','pending')")
            .bind(vec![0x11u8; 32]).bind(vec![0x22u8; 32]).execute(&pool).await.unwrap();
        let state = test_state(Some(pool.clone()), api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777));
        let coverage = history_coverage(&state).await.unwrap();
        assert_ne!(coverage.status, "complete");
        assert_eq!(coverage.deferred_decoding.unwrap().pending, 1);

        // Exercise cached decoding independently of the HTTP recovery-fence
        // deadline. An unobservable fence legitimately chooses queue receipt,
        // which is tested separately below rather than racing CI wall time.
        let response = tx_sync_now(&state, &txid, false, false).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.extensions().get::<sync_queue::Applied>().is_some());
        let body: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["indexed"], false);
        assert_eq!(body["ingested"], true);
        assert_eq!(body["decodingStatus"], "pending");
        assert_eq!(body["coverage"]["status"], "incomplete");
        let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM tn10_direct_sync_requests")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(queued, 0);

        let app = Router::new().route("/raw", get(|| async { Json(json!([])) }))
            .layer(middleware::from_fn_with_state(state, decode_coverage_headers));
        let response = app.oneshot(Request::builder().uri("/raw").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-indexer-coverage"], "incomplete");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn deferred_decode_sync_with_unobservable_fence_queues_without_claiming_ingestion(pool: PgPool) {
        let txid = "11".repeat(32);
        sqlx::query("INSERT INTO indexer_deferred_decodes(txid,block_hash,blue_score,covenant_ids,raw_transaction,reason,status) VALUES($1,$2,1,ARRAY[$1]::bytea[],'{}','unsupported_test','pending')")
            .bind(vec![0x11u8; 32]).bind(vec![0x22u8; 32]).execute(&pool).await.unwrap();
        // A missing singleton makes the real observer return None regardless
        // of database speed, including the deadline fallback under CI load.
        sqlx::query("DELETE FROM tn10_recovery_read_fence WHERE singleton")
            .execute(&pool).await.unwrap();
        assert_eq!(sync_queue::observe(&pool).await, None);
        let state = test_state(Some(pool.clone()), api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777));
        let app = Router::new().route("/tx/{txid}/sync", post(tx_sync)).with_state(state);
        let response = app.oneshot(Request::builder().uri(format!("/tx/{txid}/sync"))
            .method("POST").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["x-indexer-coverage"], "incomplete");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["txidHex"], txid);
        assert_eq!(body["indexed"], false);
        assert_eq!(body["ingested"], false);
        assert_eq!(body["pending"], true);
        assert_eq!(body["queued"], true);
        assert_eq!(body["reason"], "canonical_recovery_in_progress");
        let queued: Vec<(String, String, bool)> = sqlx::query_as("SELECT network,encode(txid,'hex'),force FROM tn10_direct_sync_requests")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(queued, vec![("testnet-10".into(), txid, false)]);
        let retained: (String, serde_json::Value) = sqlx::query_as("SELECT status,raw_transaction FROM indexer_deferred_decodes WHERE txid=$1")
            .bind(vec![0x11u8; 32]).fetch_one(&pool).await.unwrap();
        assert_eq!(retained, ("pending".into(), json!({})));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn decoding_header_fences_obligations_resolved_during_handler(pool: PgPool) {
        let state=test_state(Some(pool.clone()),api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        let app=Router::new().route("/raw",get(move || {
            let pool=pool.clone();
            async move {
                // Both middleware samples see zero pending, but the response was
                // assembled while an obligation existed. Generation must fence it.
                sqlx::query("INSERT INTO indexer_deferred_decodes(txid,block_hash,blue_score,covenant_ids,raw_transaction,reason,status) VALUES($1,$2,1,ARRAY[$1]::bytea[],'{}','test','pending')")
                    .bind(vec![0x11u8;32]).bind(vec![0x22u8;32]).execute(&pool).await.unwrap();
                let partial=json!([]);
                sqlx::query("UPDATE indexer_deferred_decodes SET status='resolved'").execute(&pool).await.unwrap();
                Json(partial)
            }
        })).layer(middleware::from_fn_with_state(state,decode_coverage_headers));
        let response=app.oneshot(Request::builder().uri("/raw").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.headers()["x-indexer-decoding-status"],"unknown");
        assert_eq!(response.headers()["x-indexer-coverage"],"incomplete");
        assert_eq!(response.headers()[header::CACHE_CONTROL],"no-store");
    }

    #[tokio::test]
    async fn decoding_header_without_persister_is_unknown() {
        let state=test_state(None,api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        let app=Router::new().route("/raw",get(||async {Json(json!([]))}))
            .layer(middleware::from_fn_with_state(state,decode_coverage_headers));
        let response=app.oneshot(Request::builder().uri("/raw").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.headers()["x-indexer-decoding-status"],"unknown");
        assert_eq!(response.headers()["x-indexer-coverage"],"incomplete");
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn clear_decoding_responses_cannot_be_cached_past_new_obligations(pool: PgPool) {
        let state=test_state(Some(pool.clone()),api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        let app=Router::new().route("/raw",get(||async {Json(json!([]))}))
            .layer(middleware::from_fn_with_state(state,decode_coverage_headers));
        let request=||Request::builder().uri("/raw").body(Body::empty()).unwrap();
        let clear=app.clone().oneshot(request()).await.unwrap();
        assert_eq!(clear.headers()["x-indexer-decoding-status"],"clear");
        assert_eq!(clear.headers()[header::CACHE_CONTROL],"no-store");
        sqlx::query("INSERT INTO indexer_deferred_decodes(txid,block_hash,blue_score,covenant_ids,raw_transaction,reason,status) VALUES($1,$2,1,ARRAY[$1]::bytea[],'{}','test','pending')")
            .bind(vec![0x11u8;32]).bind(vec![0x22u8;32]).execute(&pool).await.unwrap();
        let pending=app.oneshot(request()).await.unwrap();
        assert_eq!(pending.headers()["x-indexer-decoding-status"],"pending");
        assert_eq!(pending.headers()["x-indexer-coverage"],"incomplete");
    }

    async fn test_exclusive_recovery(pool: &PgPool, key: &str) {
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
            .bind(key).execute(pool).await.unwrap();
        tn12_indexer_db::persist::PagedRecoveryOwner::claim(pool, key, &[]).await.unwrap();
        sqlx::query("UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE WHERE intent_key=$1")
            .bind(key).execute(pool).await.unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn partial_recovery_fences_reads_and_preserves_diagnostics(pool: PgPool) {
        let state = test_state(Some(pool.clone()), api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        let app = Router::new().route("/raw", get(|| async {Json(json!({"balance": 123}))}))
            .route("/health/history", get(|| async {Json(json!({"status":"incomplete"}))}))
            .route("/readyz", get(|| async {StatusCode::OK}))
            .route("/livez", get(|| async {StatusCode::OK}))
            .layer(middleware::from_fn_with_state(state, recovery_read_fence));
        let request = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();
        let before = app.clone().oneshot(request("/raw")).await.unwrap();
        assert_eq!(before.status(), StatusCode::OK);
        assert_eq!(before.headers()[header::CACHE_CONTROL], "no-store");
        test_exclusive_recovery(&pool, "live_write_intent:test:read-fence").await;
        let during = app.clone().oneshot(request("/raw")).await.unwrap();
        assert_eq!(during.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(during.headers()["x-indexer-coverage"], "incomplete");
        assert_eq!(during.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(during.into_body(),4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("balance"));
        assert_eq!(app.clone().oneshot(request("/health/history")).await.unwrap().status(), StatusCode::OK);
        for path in ["/readyz", "/livez"] { assert_eq!(app.clone().oneshot(request(path)).await.unwrap().status(), StatusCode::OK); }
        sqlx::query("DELETE FROM tn10_live_recovery_plans").execute(&pool).await.unwrap();
        assert_eq!(app.oneshot(request("/raw")).await.unwrap().status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn recovery_generation_rejects_response_spanning_completed_plan(pool: PgPool) {
        let state = test_state(Some(pool.clone()), api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        let app = Router::new().route("/raw", get(move || {
            let pool = pool.clone();
            async move {
                test_exclusive_recovery(&pool,"live_write_intent:test:transient").await;
                let partial = Json(json!({"balance":0}));
                sqlx::query("DELETE FROM tn10_live_recovery_plans").execute(&pool).await.unwrap();
                partial
            }
        })).layer(middleware::from_fn_with_state(state,recovery_read_fence));
        let response = app.oneshot(Request::builder().uri("/raw").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL],"no-store");
        assert!(!String::from_utf8_lossy(&to_bytes(response.into_body(),4096).await.unwrap()).contains("balance"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn recovery_observation_failure_never_serves_semantic_state(pool: PgPool) {
        let state = test_state(Some(pool.clone()), api_payments::ApiPaymentPolicyCatalog::new(false,"testnet-10",777));
        sqlx::query("DELETE FROM tn10_recovery_read_fence").execute(&pool).await.unwrap();
        let app = Router::new().route("/raw",get(||async {Json(json!({"balance":123}))}))
            .layer(middleware::from_fn_with_state(state,recovery_read_fence));
        assert_eq!(app.oneshot(Request::builder().uri("/raw").body(Body::empty()).unwrap()).await.unwrap().status(),StatusCode::SERVICE_UNAVAILABLE);
    }

    include!("sync_queue_tests.rs");

}
