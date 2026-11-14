//! MCP Streamable HTTP transport (`POST /mcp`, `GET /mcp`).
//!
//! Exposes the redaction engine as an MCP tool server speaking JSON-RPC 2.0:
//! `initialize`, `ping`, `tools/list`, and `tools/call` with the
//! `redact_text` / `rehydrate_text` tools. Responses to POST requests are
//! plain JSON; `GET /mcp` upgrades to an SSE stream and advertises the POST
//! endpoint, matching the Streamable HTTP transport's happy path.

use crate::state::{build_vault, AppState};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::post,
    Json, Router,
};
use futures_core::Stream;
use pii_core::PiiVaultStore;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", post(handle_post).get(handle_get))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            state.cfg.max_body_bytes,
        ))
        .with_state(state)
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "redact_text",
            "description": "Detects PII in free text and replaces it with stable, reversible tokens.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to redact"},
                    "session_id": {"type": "string", "description": "Optional session identifier for consistent tokens"}
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "rehydrate_text",
            "description": "Restores the original values for PII tokens embedded in text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text containing PII tokens"},
                    "session_id": {"type": "string", "description": "Optional session identifier used at redaction time"}
                },
                "required": ["text"]
            }
        }),
    ]
}

/// A single JSON-RPC 2.0 request (we accept single-object payloads only).
#[derive(Debug)]
struct JsonRpcRequest {
    has_id: bool,
    id: Option<Value>,
    method: String,
    params: Value,
}

fn parse_request(body: &Value) -> Option<JsonRpcRequest> {
    let obj = body.as_object()?;
    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return None;
    }
    let method = obj.get("method")?.as_str()?.to_string();
    let has_id = obj.contains_key("id");
    let id = obj.get("id").cloned();
    Some(JsonRpcRequest {
        has_id,
        id,
        method,
        params: obj.get("params").cloned().unwrap_or(Value::Null),
    })
}

fn error_response(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {"code": code, "message": message}
    })
}

fn success_response(id: Option<Value>, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result})
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    let response = perform_request(state, headers, body).await;
    let status = response.status().as_u16().to_string();
    metrics::counter!("pii_requests_total", "endpoint" => "mcp", "status" => status).increment(1);
    metrics::histogram!("pii_request_duration_seconds", "endpoint" => "mcp")
        .record(started.elapsed().as_secs_f64());
    response
}

async fn perform_request(state: Arc<AppState>, headers: HeaderMap, body: Value) -> Response {
    let Some(req) = parse_request(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_response(None, -32600, "Invalid Request")),
        )
            .into_response();
    };

    // Notifications (missing `id`) get 202 Accepted with an empty body.
    if !req.has_id {
        return StatusCode::ACCEPTED.into_response();
    }

    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let result = match req.method.as_str() {
        "initialize" => {
            let body = json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "pii-shield", "version": env!("CARGO_PKG_VERSION")}
            });
            let mut resp = Json(success_response(req.id, body)).into_response();
            if let Some(ref sid) = session_id {
                if let Ok(hv) = axum::http::HeaderValue::from_str(sid) {
                    resp.headers_mut().insert("mcp-session-id", hv);
                }
            }
            return resp;
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => match call_tool(&state, session_id.as_deref(), &req.params).await {
            Ok(result) => result,
            Err((code, err)) => return Json(error_response(req.id, code, &err)).into_response(),
        },
        other => {
            return Json(error_response(
                req.id,
                -32601,
                &format!("Method not found: {other}"),
            ))
            .into_response()
        }
    };

    Json(success_response(req.id, result)).into_response()
}

async fn call_tool(
    state: &AppState,
    session_id: Option<&str>,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let tool = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| (-32602, "tools/call requires a 'name' string".to_string()))?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let text = args
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or_else(|| (-32602, "arguments requires a 'text' string".to_string()))?
        .to_string();

    // Tool-provided session ids win; fall back to the MCP transport header.
    let session_id = args
        .get("session_id")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| session_id.map(|s| s.to_string()));

    validate_session(state, session_id.as_deref()).map_err(|msg| (-32602, msg))?;

    let mut vault = build_vault(state, session_id.as_deref()).map_err(|e| {
        tracing::error!(error = %e, "mcp vault init failed");
        (-32001, "vault initialization failed".to_string())
    })?;

    if let (Some(store), Some(sid)) = (state.store.as_ref(), session_id.as_ref()) {
        let sid = sid.clone();
        let store = Arc::clone(store);
        let sid_task = sid.clone();
        let entries = tokio::task::spawn_blocking(move || store.get_entries(&sid_task))
            .await
            .map_err(|e| {
                tracing::warn!(?e, "mcp session load task failed");
                (-32001, "session load task failed".to_string())
            })?
            .map_err(|e| {
                tracing::warn!(?e, "mcp session load failed");
                (-32001, "session load failed".to_string())
            })?;
        vault
            .import_sealed_entries(entries.iter().map(|(t, v)| (t.as_str(), v.as_str())), &sid)
            .map_err(|e| {
                tracing::warn!(?e, "mcp session import failed");
                (-32001, "session import failed".to_string())
            })?;
    }

    let content = match tool {
        "redact_text" => {
            let (redacted, matches) = vault.redact_with_matches(&text);
            for m in &matches {
                metrics::counter!(
                    "pii_detections_total",
                    "entity_type" => m.entity_type.as_tag_prefix().to_string()
                )
                .increment(1);
            }
            if let Some(sid) = session_id.as_ref().filter(|_| state.store.is_some()) {
                flush(state, &mut vault, sid)
                    .await
                    .map_err(|msg| (-32001, msg))?;
            }
            json!({"redacted_text": redacted})
        }
        "rehydrate_text" => {
            let restored = vault.rehydrate(&text);
            json!({"text": restored})
        }
        other => return Err((-32602, format!("Unknown tool: {other}"))),
    };

    Ok(json!({
        "content": [{"type": "text", "text": serde_json::to_string(&content).unwrap_or_default()}],
        "isError": false
    }))
}

/// Session IDs are used directly as store keys; reject anything dangerous, and
/// require `session_id` when Redis backing store is active.
fn validate_session(state: &AppState, session_id: Option<&str>) -> Result<(), String> {
    match session_id {
        Some(id) => {
            if id.is_empty()
                || id.len() > 128
                || id
                    .chars()
                    .any(|c| c == ':' || c.is_whitespace() || c.is_control())
            {
                return Err("session_id must be 1-128 chars without ':' or whitespace".to_string());
            }
        }
        None if state.store.is_some() => {
            return Err("session_id is required when PII_TOKEN_FORMAT=redis".to_string());
        }
        None => {}
    }
    Ok(())
}

async fn flush(
    state: &AppState,
    vault: &mut pii_core::PiiSessionVault,
    session_id: &str,
) -> Result<(), String> {
    let store = Arc::clone(state.store.as_ref().unwrap());
    let sealed = vault.seal_dirty_entries(session_id);
    if sealed.is_empty() {
        return Ok(());
    }
    let dirty_tokens: Vec<String> = sealed.iter().map(|(t, _)| t.clone()).collect();
    let sid = session_id.to_string();
    // Redis I/O must not block the Tokio runtime worker threads.
    tokio::task::spawn_blocking(move || store.put_entries(&sid, sealed))
        .await
        .map_err(|e| {
            tracing::warn!(?e, "mcp session flush task failed");
            "session flush task failed".to_string()
        })?
        .map_err(|e| {
            tracing::warn!(?e, "mcp session flush failed");
            "session flush failed".to_string()
        })?;
    vault.clear_dirty_tokens(&dirty_tokens);
    Ok(())
}

/// `GET /mcp`: opens an SSE stream, sends the `endpoint` event pointing at
/// `/mcp`, then stays open until the client disconnects or the process
/// begins shutting down (so graceful shutdown never stalls on open streams).
async fn handle_get(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>> + Send> {
    Sse::new(endpoint_event_stream(state.shutdown.clone())).keep_alive(KeepAlive::default())
}

fn endpoint_event_stream(
    shutdown: watch::Receiver<bool>,
) -> impl Stream<Item = Result<Event, Infallible>> + Send {
    async_stream::stream! {
        let mut shutdown = shutdown;
        yield Ok(Event::default().event("endpoint").data("/mcp"));
        // Keep the transport open until the client disconnects or shutdown.
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = shutdown.changed() => break,
            }
        }
    }
}
