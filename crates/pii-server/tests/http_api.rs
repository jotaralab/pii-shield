//! Integration tests for the `pii-server` HTTP + MCP API.
//!
//! Exercises the full router in-process with sealed-token configuration,
//! plus the graceful shutdown of the real binary via SIGTERM.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::util::ServiceExt;

fn test_state() -> std::sync::Arc<pii_server::state::AppState> {
    // AppState::build installs the global prometheus recorder exactly once.
    static STATE: std::sync::OnceLock<std::sync::Arc<pii_server::state::AppState>> =
        std::sync::OnceLock::new();
    STATE
        .get_or_init(|| {
            let cfg = pii_server::config::Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                token_format: pii_core::TokenFormat::StatelessSealed,
                seal_key: Some(zeroize::Zeroizing::new([42u8; 32])),
                redis_url: None,
                max_body_bytes: 1_024, // small on purpose, to test the body limit
                log_format: pii_server::config::LogFormat::Json,
                locales: vec![
                    "global".into(),
                    "id".into(),
                    "us".into(),
                    "eu".into(),
                    "sg".into(),
                ],
            };
            std::sync::Arc::new(pii_server::state::AppState::build(cfg).unwrap())
        })
        .clone()
}

fn app() -> axum::Router {
    pii_server::api::router(test_state()).merge(pii_server::mcp::router(test_state()))
}

async fn post_json(uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    decode(response).await
}

async fn get(uri: &str) -> (StatusCode, Value) {
    let response = app()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    decode(response).await
}

async fn decode(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (status, body) = get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ok"}));
}

#[tokio::test]
async fn readyz_ready_without_store() {
    let (status, body) = get("/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"status": "ready"}));
}

#[tokio::test]
async fn metrics_exposes_prometheus_format() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; version=0.0.4"
    );
}

#[tokio::test]
async fn redact_and_rehydrate_round_trip() {
    let text = "Contact ada@example.com about account #4411";
    let (status, body) = post_json("/v1/redact", json!({"text": text})).await;
    assert_eq!(status, StatusCode::OK);
    let redacted = body["redacted_text"].as_str().unwrap();
    assert!(
        !redacted.contains("ada@example.com"),
        "raw PII leaked: {redacted}"
    );
    assert!(
        redacted.contains("<PII:EMAIL:"),
        "expected token: {redacted}"
    );
    assert!(body["entities"].is_array());

    let (status, body) = post_json("/v1/rehydrate", json!({"text": redacted})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["text"].as_str().unwrap(), text);
}

#[tokio::test]
async fn redact_rejects_invalid_json() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/redact")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let big = "x".repeat(4_096); // > max_body_bytes (1024)
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/redact")
                .header("content-type", "application/json")
                .body(Body::from(json!({"text": big}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn mcp_initialize_and_tool_call_round_trip() {
    let (status, body) = post_json(
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["serverInfo"]["name"], "pii-shield");

    let (status, body) = post_json(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["redact_text", "rehydrate_text"]);

    let (status, body) = post_json(
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "redact_text", "arguments": {"text": "email bob@example.com"}}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let content = body["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(content).unwrap();
    let redacted = parsed["redacted_text"].as_str().unwrap();
    assert!(
        !redacted.contains("bob@example.com"),
        "raw PII leaked: {redacted}"
    );

    let (status, body) = post_json(
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "rehydrate_text", "arguments": {"text": redacted}}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let content = body["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(content).unwrap();
    assert_eq!(parsed["text"].as_str().unwrap(), "email bob@example.com");
}

#[tokio::test]
async fn mcp_rejects_invalid_session_id() {
    let (status, body) = post_json(
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "redact_text",
                       "arguments": {"text": "email ada@example.com",
                                     "session_id": "bad: id\n"}}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], -32602);
}

#[tokio::test]
async fn mcp_echoes_session_header_and_handles_null_id_vs_notification() {
    let router = app();

    // 1. initialize echoes mcp-session-id header when provided
    let res_init = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("mcp-session-id", "sess-mcp-42")
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_init.status(), StatusCode::OK);
    assert_eq!(
        res_init
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok()),
        Some("sess-mcp-42")
    );

    // 2. Notification (missing "id") returns 202 Accepted
    let (notif_status, _) = post_json(
        "/mcp",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif_status, StatusCode::ACCEPTED);

    // 3. Request with explicit `"id": null` returns 200 OK with `"id": null`
    let (null_id_status, null_id_body) = post_json(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
    )
    .await;
    assert_eq!(null_id_status, StatusCode::OK);
    assert!(null_id_body["id"].is_null());
    assert!(null_id_body["result"].is_object());
}

#[tokio::test]
async fn mcp_unknown_method_returns_json_rpc_error() {
    let (status, body) = post_json(
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 9, "method": "bogus/method"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], -32601);
}

#[tokio::test]
async fn graceful_shutdown_drains_on_sigterm() {
    // Spawn the real binary and verify SIGTERM terminates it with code 0.
    let bin = env!("CARGO_BIN_EXE_pii-server");
    let mut child = std::process::Command::new(bin)
        .env("PII_BIND_ADDR", "127.0.0.1:18081")
        .env("PII_SEAL_KEY", "ab".repeat(32))
        .spawn()
        .expect("failed to spawn pii-server");

    // Wait for the server socket to become reachable rather than sleeping blindly.
    for _ in 0..50 {
        if std::net::TcpStream::connect("127.0.0.1:18081").is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };

    let status = child.wait().unwrap();
    assert!(status.success(), "expected clean exit, got: {status:?}");
}

#[tokio::test]
async fn redact_detects_indonesian_nik_by_default() {
    let (status, body) = post_json("/v1/redact", json!({"text": "NIK: 3573012203950001"})).await;
    assert_eq!(status, StatusCode::OK);
    let redacted = body["redacted_text"].as_str().unwrap();
    assert!(redacted.contains("<PII:ID_NIK:"), "got {redacted}");
}

#[tokio::test]
async fn stateless_sealed_binds_session_id_when_provided() {
    let (status, body) = post_json(
        "/v1/redact",
        json!({"text": "Contact ada@example.com", "session_id": "tenant-a"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let redacted = body["redacted_text"].as_str().unwrap().to_string();

    // Same session_id rehydrates cleanly.
    let (r_status, r_body) = post_json(
        "/v1/rehydrate",
        json!({"text": redacted, "session_id": "tenant-a"}),
    )
    .await;
    assert_eq!(r_status, StatusCode::OK);
    assert_eq!(r_body["text"], "Contact ada@example.com");

    // Different session_id must NOT decrypt tenant-a's token.
    let (x_status, x_body) = post_json(
        "/v1/rehydrate",
        json!({"text": redacted, "session_id": "tenant-b"}),
    )
    .await;
    assert_eq!(x_status, StatusCode::OK);
    assert_eq!(x_body["text"], redacted);
}

#[tokio::test]
async fn redis_mode_rejects_missing_session_id_with_400() {
    let server = pii_store_redis::test_support::MockValkey::start();
    let cfg = pii_server::config::Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        token_format: pii_core::TokenFormat::CompactHash,
        seal_key: Some(zeroize::Zeroizing::new([77u8; 32])),
        redis_url: Some(server.url()),
        max_body_bytes: 1_048_576,
        log_format: pii_server::config::LogFormat::Json,
        locales: vec![
            "global".into(),
            "id".into(),
            "us".into(),
            "eu".into(),
            "sg".into(),
        ],
    };
    let state = std::sync::Arc::new(pii_server::state::AppState::build(cfg).unwrap());
    let router = pii_server::api::router(state.clone()).merge(pii_server::mcp::router(state));

    // HTTP /v1/redact without session_id returns 400 Bad Request
    let res_missing = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/redact")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"text": "Customer ada@example.com"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_missing.status(), StatusCode::BAD_REQUEST);

    // MCP tools/call without session_id returns JSON-RPC -32602
    let res_mcp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {
                            "name": "redact_text",
                            "arguments": {"text": "Customer ada@example.com"}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (mcp_status, mcp_body) = decode(res_mcp).await;
    assert_eq!(mcp_status, StatusCode::OK);
    assert_eq!(mcp_body["error"]["code"], -32602);
}

#[tokio::test]
async fn redis_mode_persists_and_rehydrates_across_requests() {
    let server = pii_store_redis::test_support::MockValkey::start();
    let cfg = pii_server::config::Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        token_format: pii_core::TokenFormat::CompactHash,
        seal_key: Some(zeroize::Zeroizing::new([77u8; 32])),
        redis_url: Some(server.url()),
        max_body_bytes: 1_048_576,
        log_format: pii_server::config::LogFormat::Json,
        locales: vec![
            "global".into(),
            "id".into(),
            "us".into(),
            "eu".into(),
            "sg".into(),
        ],
    };
    let state = std::sync::Arc::new(pii_server::state::AppState::build(cfg).unwrap());
    let router = pii_server::api::router(state.clone()).merge(pii_server::mcp::router(state));

    // With session_id, redaction persists to Redis and subsequent rehydrate restores it.
    let res_redact = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/redact")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"text": "Customer ada@example.com", "session_id": "sess-redis-1"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = decode(res_redact).await;
    assert_eq!(status, StatusCode::OK);
    let redacted = body["redacted_text"].as_str().unwrap().to_string();
    assert!(redacted.contains("<EMAIL_"), "got {redacted}");

    let res_rehydrate = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/rehydrate")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"text": redacted, "session_id": "sess-redis-1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (r_status, r_body) = decode(res_rehydrate).await;
    assert_eq!(r_status, StatusCode::OK);
    assert_eq!(r_body["text"], "Customer ada@example.com");
}
