//! Read fencing for an in-place V2 database. The coordination SHARE lock spans
//! the entire handler, including reads performed on other pooled connections.
use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct ShadowApi {
    pub pool: PgPool,
    admission: Arc<Semaphore>,
    deadline: Duration,
}
impl ShadowApi {
    pub fn new(pool: PgPool) -> anyhow::Result<Self> {
        let capacity = pool.options().get_max_connections();
        anyhow::ensure!(
            capacity >= 2,
            "shadow API needs at least two database connections"
        );
        // Each admitted request holds a fence connection while its handler uses
        // another connection. Reserve capacity before taking the first lock.
        Ok(Self {
            pool,
            admission: Arc::new(Semaphore::new((capacity / 2).min(4) as usize)),
            deadline: Duration::from_secs(10),
        })
    }
    #[cfg(test)]
    pub fn with_test_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }
}

pub async fn fence(State(state): State<ShadowApi>, request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }
    let _permit = match state.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"shadow_api_busy"})),
            )
                .into_response()
        }
    };
    match tokio::time::timeout(state.deadline, fenced_read(state, request, next)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"error":"shadow_read_timeout"})),
        )
            .into_response(),
    }
}

async fn fenced_read(state: ShadowApi, request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({"error":"shadow_read_only"})),
        )
            .into_response();
    }
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return unavailable(),
    };
    if sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return unavailable();
    }
    let row=match sqlx::query("SELECT ready,generation,active_plan,checkpoint_score,history_start_score,history_start_ms,seed_manifest,revision,retained_bytes,epoch,source_checked_at::text FROM shadow_v2.control FOR SHARE")
        .fetch_one(&mut *tx).await {Ok(row)=>row,Err(_)=>return unavailable()};
    let ready = row.get::<bool, _>("ready") && row.get::<Option<i64>, _>("active_plan").is_none();
    let generation = row.get::<i64, _>("generation");
    let start = row
        .get::<Option<i64>, _>("history_start_score")
        .unwrap_or(0);
    let start_ms = row
        .get::<Option<i64>, _>("history_start_ms")
        .unwrap_or(i64::MAX);
    let path = request.uri().path();
    if path == "/metrics" {
        let metrics=format!("shadow_ready {}\nshadow_generation {}\nshadow_epoch {}\nshadow_revision {}\nshadow_retained_evidence_bytes {}\n",u8::from(ready),generation,row.get::<i64,_>("epoch"),row.get::<i64,_>("revision"),row.get::<i64,_>("retained_bytes"));
        return ([("content-type", "text/plain; version=0.0.4")], metrics).into_response();
    }
    if matches!(
        path,
        "/health" | "/health/live" | "/health/history" | "/readyz" | "/livez"
    ) {
        let status = if path == "/livez" || (ready && path != "/health/history") {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        return (
            status,
            Json(
                json!({"ready":ready,"generation":generation,"historyComplete":false,
            "historyStartBlueScore":start,"historySource":"seeded-current-state-and-forward",
            "reason":if ready {"ok"} else {"recovery_in_progress"}}),
            ),
        )
            .into_response();
    }
    if !ready {
        return unavailable();
    }
    // Existing time-filtered contracts keep their JSON shape. Requests that
    // explicitly reach before the verified forward boundary fail, not truncate.
    let query =
        match axum::extract::Query::<std::collections::BTreeMap<String, String>>::try_from_uri(
            request.uri(),
        ) {
            Ok(query) => query.0,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"invalid_query"})),
                )
                    .into_response()
            }
        };
    if query
        .get("from")
        .and_then(|v| v.parse::<i64>().ok())
        .is_some_and(|v| v < start_ms)
    {
        return (StatusCode::CONFLICT,Json(json!({"error":"history_outside_coverage","historyStartBlueScore":start,"historyStartMs":start_ms}))).into_response();
    }
    // A missing lower bound is not proof of complete history. Keep the
    // current-state allowlist explicit so newly added routes fail closed.
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    let current_only = matches!(
        parts.as_slice(),
        ["utxos"]
            | ["covenant-templates"]
            | ["addresses", _, "utxos"]
            | ["covenants", _, "utxos"]
            | ["covenants", "by-id", _, "utxos"]
            | ["kcc20", _, "utxos"]
    );
    let bounded_history = matches!(parts.as_slice(), ["kcc20", _, "activity" | "candles"])
        && query
            .get("from")
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|v| v >= start_ms);
    let transaction_lookup = matches!(parts.as_slice(), ["tx", _] | ["tx", _, "context"]);
    if !current_only && !bounded_history && !transaction_lookup {
        return (StatusCode::CONFLICT, Json(json!({"error":"history_outside_coverage",
            "historyStartBlueScore":start,"historyStartMs":start_ms,
            "reason":"route requires historical coverage not certified by the current-state seed"}))).into_response();
    }
    if let Some(txid) = path.strip_prefix("/tx/").and_then(|s| s.split('/').next()) {
        if txid.len() == 64 {
            let covered = match hex::decode(txid) {
                Ok(id) => sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM shadow_v2.acceptance_events WHERE txid=$1)",
                )
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(false),
                Err(_) => false,
            };
            if !covered {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error":"transaction_outside_verified_coverage"})),
                )
                    .into_response();
            }
        }
    }
    let mut response = next.run(request).await;
    // Axum JSON handlers materialize their response before returning. Holding
    // this transaction prevents guarded state changes across all handler reads.
    if tx.commit().await.is_err() {
        return unavailable();
    }
    for (name, value) in [
        ("x-shadow-generation", generation.to_string()),
        ("x-history-start-blue-score", start.to_string()),
        (
            "x-history-source",
            "seeded-current-state-and-forward".into(),
        ),
    ] {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"shadow_recovery_in_progress"})),
    )
        .into_response()
}
