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
        .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
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
    assert!(!redacted.contains("ada@example.com"), "raw PII leaked: {redacted}");
    assert!(redacted.contains("<PII:EMAIL:"), "expected token: {redacted}");
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

    let (status, body) = post_json("/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
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
    assert!(!redacted.contains("bob@example.com"), "raw PII leaked: {redacted}");

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
async fn mcp_unknown_method_returns_json_rpc_error() {
    let (status, body) = post_json("/mcp", json!({"jsonrpc": "2.0", "id": 9, "method": "bogus/method"})).await;
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

    // Give the server a moment to bind.
    std::thread::sleep(std::time::Duration::from_millis(400));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };

    let status = child.wait().unwrap();
    assert!(status.success(), "expected clean exit, got: {status:?}");
}
