// Included in the API's existing test module so these exercise its actual
// authentication, handlers, persister, and disposable migrated database.
const QUEUED_TXID: &str = "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0";

async fn queue_fence(pool: &PgPool) {
    sqlx::query("INSERT INTO tn10_live_recovery_plans(intent_key,intent_sha256,owner_token,lease_expires_at_ms,phase,updated_at_ms) VALUES('live_write_intent:testnet-10:queue-test',sha256('{}'::bytea),gen_random_uuid(),9999999999999,'revert',1) ON CONFLICT DO NOTHING")
        .execute(pool).await.unwrap();
    sqlx::query("UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE")
        .execute(pool)
        .await
        .unwrap();
}

async fn queue_len(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM tn10_direct_sync_requests")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn queue_app(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(|| async { Json(json!({"balance":10})) }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            recovery_read_fence,
        ))
        .route("/tx/{txid}/sync", post(tx_sync))
        .with_state(state)
}

async fn queue_rest(
    pool: PgPool,
    mode: &'static str,
) -> (RestClient, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/transactions/{txid}",
        get(move |Path(txid): Path<String>, headers: HeaderMap| {
            let hits = seen.clone();
            let pool = pool.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                assert_eq!(txid, QUEUED_TXID);
                assert!(headers[header::CACHE_CONTROL]
                    .to_str()
                    .unwrap()
                    .contains("no-cache"));
                if mode == "missing" {
                    return StatusCode::NOT_FOUND.into_response();
                }
                if mode == "force-upgrade" {
                    sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, true)
                        .await
                        .unwrap()
                }
                if mode == "fence-after-fetch" {
                    queue_fence(&pool).await
                }
                let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
                    "../../../fixtures/api-payment-channel-tn10/01-settlement-open.json"
                ))
                .unwrap();
                if mode == "unaccepted" {
                    fixture["is_accepted"] = json!(false);
                }
                let mut response = Json(fixture).into_response();
                if mode == "stale" {
                    response.headers_mut().insert(
                        header::DATE,
                        HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
                    );
                }
                response
            }
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        RestClient::new(format!("http://{address}")).unwrap(),
        task,
        hits,
    )
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn sync_during_recovery_queues_only_authenticated_valid_requests(pool: PgPool) {
    queue_fence(&pool).await;
    let state = test_state_with_rest_and_sync_guard(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        None,
        ApiPaymentChannelSyncGuard::new(Some("queue-test-token".into()), 3),
    );
    let app = queue_app(state);
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/tx/{QUEUED_TXID}/sync"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(queue_len(&pool).await, 0);
    for suffix in ["", "", "?force=true"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/tx/{QUEUED_TXID}/sync{suffix}"))
                    .header(header::AUTHORIZATION, "Bearer queue-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(value["queued"], true);
        assert_eq!(value["indexed"], false);
        assert_eq!(value["ingested"], false);
        assert_eq!(value["reason"], "canonical_recovery_in_progress");
    }
    let limited = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/tx/{QUEUED_TXID}/sync"))
                .header(header::AUTHORIZATION, "Bearer queue-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tx/invalid/sync")
                .header(header::AUTHORIZATION, "Bearer queue-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(queue_len(&pool).await, 1);
    let (force, revision): (bool, i64) =
        sqlx::query_as("SELECT force,revision FROM tn10_direct_sync_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(force);
    assert_eq!(revision, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT pending FROM tn10_direct_sync_capacity")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let read = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_survives_restart_and_two_consumers_drain_after_recovery(pool: PgPool) {
    queue_fence(&pool).await;
    let initial = test_state(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
    );
    let response = queue_app(initial)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/tx/{QUEUED_TXID}/sync"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let (rest, server, hits) = queue_rest(pool.clone(), "ok").await;
    // New runtime state, same durable database. A live recovery must prevent even fetching.
    let restarted = test_state_with_rest(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        Some(rest),
    );
    assert!(!sync_queue::drain_one(&restarted).await.unwrap());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    sqlx::query("DELETE FROM tn10_live_recovery_plans")
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        sync_queue::drain_one(&restarted),
        sync_queue::drain_one(&restarted)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(a || b);
    assert_eq!(queue_len(&pool).await, 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT pending FROM tn10_direct_sync_capacity")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_retains_missing_stale_and_recovery_racing_source(pool: PgPool) {
    for mode in ["missing", "stale", "fence-after-fetch"] {
        sqlx::query("DELETE FROM tn10_live_recovery_plans")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE tn10_direct_sync_requests SET next_attempt_at_ms=0,lease_until_ms=0")
            .execute(&pool)
            .await
            .unwrap();
        sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false)
            .await
            .unwrap();
        let (rest, server, _) = queue_rest(pool.clone(), mode).await;
        let state = test_state_with_rest(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        );
        sync_queue::drain_one(&state).await.unwrap();
        assert_eq!(queue_len(&pool).await, 1, "{mode}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_actions")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "{mode}"
        );
        server.abort();
    }
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_commit_before_ack_failure_replays_idempotently(pool: PgPool) {
    sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION queue_test_ack_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected queue ack failure'; END $$; CREATE TRIGGER queue_test_ack_failure BEFORE DELETE ON tn10_direct_sync_requests FOR EACH ROW EXECUTE FUNCTION queue_test_ack_failure();")
        .execute(&pool).await.unwrap();
    let (rest, server, hits) = queue_rest(pool.clone(), "ok").await;
    let state = test_state_with_rest(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        Some(rest),
    );
    assert!(sync_queue::drain_one(&state).await.is_err());
    assert_eq!(queue_len(&pool).await, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DROP TRIGGER queue_test_ack_failure ON tn10_direct_sync_requests")
        .execute(&pool)
        .await
        .unwrap();
    // Simulate lease expiry after process loss, without a five-minute test sleep.
    sqlx::query("UPDATE tn10_direct_sync_requests SET lease_until_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sync_queue::drain_one(&state).await.unwrap());
    assert_eq!(queue_len(&pool).await, 0);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "retry must verify fresh acceptance even after the first canonical commit"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_force_upgrade_is_not_acknowledged_by_an_older_claim(pool: PgPool) {
    sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false)
        .await
        .unwrap();
    let (rest, server, hits) = queue_rest(pool.clone(), "force-upgrade").await;
    let state = test_state_with_rest(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        Some(rest),
    );
    assert!(sync_queue::drain_one(&state).await.unwrap());
    assert_eq!(queue_len(&pool).await, 1);
    sqlx::query("UPDATE tn10_direct_sync_requests SET next_attempt_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sync_queue::drain_one(&state).await.unwrap());
    assert_eq!(queue_len(&pool).await, 0);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_capacity_and_database_failure_never_acknowledge_unsaved_work(pool: PgPool) {
    queue_fence(&pool).await;
    // Tighten the disposable DB constraint to exercise concurrent full admission.
    sqlx::query("ALTER TABLE tn10_direct_sync_capacity ADD CHECK(pending<=1)")
        .execute(&pool)
        .await
        .unwrap();
    let other = "33".repeat(32);
    let (a, b) = tokio::join!(
        sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false),
        sync_queue::enqueue(&pool, "testnet-10", &other, false)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(queue_len(&pool).await, 1);
    let id: String = sqlx::query_scalar("SELECT encode(txid,'hex') FROM tn10_direct_sync_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    sync_queue::enqueue(&pool, "testnet-10", &id, false)
        .await
        .unwrap();
    let state = test_state(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
    );
    let app = queue_app(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/tx/{}/sync", "44".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    sqlx::query("ALTER TABLE tn10_direct_sync_requests RENAME TO unavailable_sync_requests")
        .execute(&pool)
        .await
        .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/tx/{QUEUED_TXID}/sync"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_existing_actions_still_require_fresh_accepted_source(pool: PgPool) {
    let tx: RestTransaction = serde_json::from_str(include_str!(
        "../../../fixtures/api-payment-channel-tn10/01-settlement-open.json"
    ))
    .unwrap();
    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();
    sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false)
        .await
        .unwrap();
    for mode in ["missing", "stale", "unaccepted"] {
        sqlx::query("UPDATE tn10_direct_sync_requests SET next_attempt_at_ms=0")
            .execute(&pool)
            .await
            .unwrap();
        let (rest, server, hits) = queue_rest(pool.clone(), mode).await;
        let state = test_state_with_rest(
            Some(pool.clone()),
            api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
            Some(rest),
        );
        sync_queue::drain_one(&state).await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "{mode} must not use local actions as source proof"
        );
        assert_eq!(
            queue_len(&pool).await,
            1,
            "{mode} cannot acknowledge the request"
        );
        server.abort();
    }
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn queued_sync_reclaims_lost_sessions_without_waiting_for_lease_expiry(pool: PgPool) {
    sync_queue::enqueue(&pool, "testnet-10", QUEUED_TXID, false)
        .await
        .unwrap();
    sqlx::query("UPDATE tn10_direct_sync_requests SET lease_token=gen_random_uuid(),lease_until_ms=9999999999999")
        .execute(&pool).await.unwrap();
    let (rest, server, hits) = queue_rest(pool.clone(), "ok").await;
    let state = test_state_with_rest(
        Some(pool.clone()),
        api_payments::ApiPaymentPolicyCatalog::new(false, "testnet-10", 777),
        Some(rest),
    );
    let mut owner = pool.acquire().await.unwrap();
    owner.close_on_drop();
    let key = format!("testnet-10:{QUEUED_TXID}");
    sqlx::query("SELECT pg_advisory_lock(1415074641,hashtext($1))")
        .bind(&key)
        .execute(&mut *owner)
        .await
        .unwrap();
    assert!(
        !sync_queue::drain_one(&state).await.unwrap(),
        "a live owner cannot be replaced"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    sqlx::query("SELECT pg_advisory_unlock(1415074641,hashtext($1))")
        .bind(&key)
        .execute(&mut *owner)
        .await
        .unwrap();
    owner.close().await.unwrap();
    assert!(
        sync_queue::drain_one(&state).await.unwrap(),
        "a lost owner must not impose a five-minute delay"
    );
    assert_eq!(queue_len(&pool).await, 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    server.abort();
}
