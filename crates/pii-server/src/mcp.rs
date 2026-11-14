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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mcp", post(handle_post).get(handle_get))
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
    id: Option<Value>,
    method: String,
    params: Value,
}

fn parse_request(body: &Value) -> Option<JsonRpcRequest> {
    let obj = body.as_object()?;
    let method = obj.get("method")?.as_str()?.to_string();
    Some(JsonRpcRequest {
        id: obj.get("id").cloned().filter(|id| !id.is_null()),
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
    let Some(req) = parse_request(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_response(None, -32600, "Invalid Request")),
        )
            .into_response();
    };

    // Notifications (no id) get 202 Accepted with an empty body.
    if req.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }

    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let result = match req.method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "pii-shield", "version": env!("CARGO_PKG_VERSION")}
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => match call_tool(&state, session_id.as_deref(), &req.params).await {
            Ok(result) => result,
            Err(err) => return Json(error_response(req.id, -32001, &err)).into_response(),
        },
        other => {
            return Json(error_response(req.id, -32601, &format!("Method not found: {other}")))
                .into_response()
        }
    };

    Json(success_response(req.id, result)).into_response()
}

async fn call_tool(
    state: &AppState,
    session_id: Option<&str>,
    params: &Value,
) -> Result<Value, String> {
    let tool = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or("tools/call requires a 'name' string")?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let text = args
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or("arguments requires a 'text' string")?
        .to_string();

    // Tool-provided session ids win; fall back to the MCP transport header.
    let session_id = args
        .get("session_id")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .or_else(|| session_id.map(|s| s.to_string()));

    let mut vault =
        build_vault(&state.cfg).map_err(|e| format!("vault init failed: {e}"))?;

    if state.store.is_some() && session_id.is_some() {
        let sid = session_id.clone().unwrap();
        let store = Arc::clone(state.store.as_ref().unwrap());
        let sid_task = sid.clone();
        let entries = tokio::task::spawn_blocking(move || store.get_entries(&sid_task))
            .await
            .map_err(|e| format!("session load task failed: {e}"))?
            .map_err(|e| format!("session load failed: {e:?}"))?;
        vault
            .import_sealed_entries(entries.iter().map(|(t, v)| (t.as_str(), v.as_str())), &sid)
            .map_err(|e| format!("session import failed: {e:?}"))?;
    }

    let content = match tool {
        "redact_text" => {
            let redacted = vault.redact(&text);
            if state.store.is_some() && session_id.is_some() {
                flush(state, &mut vault, session_id.as_ref().unwrap()).await?;
            }
            json!({"redacted_text": redacted})
        }
        "rehydrate_text" => {
            let restored = vault.rehydrate(&text);
            json!({"text": restored})
        }
        other => return Err(format!("Unknown tool: {other}")),
    };

    Ok(json!({
        "content": [{"type": "text", "text": serde_json::to_string(&content).unwrap_or_default()}],
        "isError": false
    }))
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
    let sid = session_id.to_string();
    store
        .put_entries(&sid, sealed)
        .map_err(|e| format!("session flush failed: {e:?}"))?;
    Ok(())
}

/// `GET /mcp`: opens an SSE stream, sends the `endpoint` event pointing at
/// `/mcp`, then stays open (keep-alives keep the connection alive until the
/// client disconnects).
async fn handle_get() -> Sse<impl Stream<Item = Result<Event, Infallible>> + Send> {
    Sse::new(endpoint_event_stream()).keep_alive(KeepAlive::default())
}

fn endpoint_event_stream() -> impl Stream<Item = Result<Event, Infallible>> + Send {
    async_stream::stream! {
        yield Ok(Event::default().event("endpoint").data("/mcp"));
        // Stream intentionally never completes: the transport keeps it open
        // and axum tears it down when the client disconnects.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    }
}
