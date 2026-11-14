//! HTTP/JSON API routes: `/healthz`, `/readyz`, `/metrics`, `/v1/redact`,
//! `/v1/rehydrate`.

use crate::state::{build_vault, AppState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use metrics::histogram;
use pii_core::PiiVaultStore;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tower_http::limit::RequestBodyLimitLayer;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/redact", post(redact))
        .route("/v1/rehydrate", post(rehydrate))
        .layer(RequestBodyLimitLayer::new(state.cfg.max_body_bytes))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

async fn healthz() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    if let Some(store) = &state.store {
        let store = Arc::clone(store);
        let result = tokio::task::spawn_blocking(move || {
            // Round-trip against Redis: an unknown probe session key returns
            // an empty entry list, which acts as a cheap PING.
            store.get_entries("__pii_readyz__")
        })
        .await;
        match result {
            Ok(Ok(_)) => Json(json!({"status": "ready"})).into_response(),
            Ok(Err(err)) => {
                tracing::warn!(?err, "readyz: redis ping failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"status": "not_ready", "error": err.to_string()})),
                )
                    .into_response()
            }
            Err(join_err) => {
                tracing::warn!(?join_err, "readyz: redis task panicked");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"status": "not_ready", "error": "internal error"})),
                )
                    .into_response()
            }
        }
    } else {
        Json(json!({"status": "ready"})).into_response()
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.prometheus.render(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Redact / rehydrate
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TextRequest {
    text: String,
    session_id: Option<String>,
}

fn invalid_session(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

fn internal(msg: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": msg})),
    )
        .into_response()
}

async fn redact(State(state): State<Arc<AppState>>, Json(req): Json<TextRequest>) -> Response {
    let started = Instant::now();
    let response = perform_redact(&state, req).await;
    record(&state, "redact".to_string(), &response, started, true);
    response
}

async fn rehydrate(State(state): State<Arc<AppState>>, Json(req): Json<TextRequest>) -> Response {
    let started = Instant::now();
    let response = perform_rehydrate(&state, req).await;
    record(&state, "rehydrate".to_string(), &response, started, false);
    response
}

fn record(
    state: &AppState,
    endpoint: String,
    response: &Response,
    started: Instant,
    count_detections: bool,
) {
    let status = response.status().as_u16().to_string();
    metrics::counter!("pii_requests_total", "endpoint" => endpoint.clone(), "status" => status)
        .increment(1);
    histogram!("pii_request_duration_seconds", "endpoint" => endpoint)
        .record(started.elapsed().as_secs_f64());

    if count_detections {
        if let Some(count) = response.extensions().get::<DetectionsCount>() {
            for (entity_type, hits) in count.0.iter() {
                metrics::counter!(
                    "pii_detections_total",
                    "entity_type" => entity_type.as_tag_prefix().to_string()
                )
                .increment(*hits);
            }
        }
    }
    let _ = state; // state kept in scope for future label enrichments
}

/// Number of detections per entity type, attached to the response extensions
/// so the outer handler can emit metrics after the response is built.
#[derive(Clone)]
pub struct DetectionsCount(Vec<(pii_core::EntityType, u64)>);

async fn perform_redact(state: &AppState, req: TextRequest) -> Response {
    if let Some(resp) = validate_session(state, &req.session_id) {
        return resp;
    }

    let matches = state.scanner.scan(&req.text);
    let mut counts: Vec<(pii_core::EntityType, u64)> = Vec::new();
    for m in &matches {
        match counts.iter_mut().find(|(t, _)| t == &m.entity_type) {
            Some((_, hits)) => *hits += 1,
            None => counts.push((m.entity_type.clone(), 1)),
        }
    }

    let mut vault = match build_vault(&state.cfg) {
        Ok(v) => v,
        Err(e) => return internal(&format!("vault init failed: {e}")),
    };

    // Load prior session entries so tokens stay consistent across calls.
    let session_id = req.session_id.clone().unwrap_or_else(|| "_anon".into());
    if state.store.is_some() && req.session_id.is_some() {
        if let Some(resp) = load_session(state, &mut vault, &session_id).await {
            return resp;
        }
    }

    let redacted_text = vault.redact(&req.text);

    if state.store.is_some() && req.session_id.is_some() {
        if let Some(resp) = flush_session(state, &mut vault, &session_id).await {
            return resp;
        }
    }

    let mut response = Json(json!({
        "redacted_text": redacted_text,
        "entities": matches,
    }))
    .into_response();
    response.extensions_mut().insert(DetectionsCount(counts));
    response
}

async fn perform_rehydrate(state: &AppState, req: TextRequest) -> Response {
    if let Some(resp) = validate_session(state, &req.session_id) {
        return resp;
    }

    let mut vault = match build_vault(&state.cfg) {
        Ok(v) => v,
        Err(e) => return internal(&format!("vault init failed: {e}")),
    };

    let session_id = req.session_id.clone().unwrap_or_else(|| "_anon".into());
    if state.store.is_some() && req.session_id.is_some() {
        if let Some(resp) = load_session(state, &mut vault, &session_id).await {
            return resp;
        }
    }

    let text = vault.rehydrate(&req.text);

    Json(json!({"text": text})).into_response()
}

/// Session IDs are used directly as store keys; reject anything dangerous.
fn validate_session(state: &AppState, session_id: &Option<String>) -> Option<Response> {
    if let Some(id) = session_id {
        if id.is_empty()
            || id.len() > 128
            || id
                .chars()
                .any(|c| c == ':' || c.is_whitespace() || c.is_control())
        {
            return Some(invalid_session(
                "session_id must be 1-128 chars without ':' or whitespace",
            ));
        }
    }
    if state.store.is_none() && session_id.is_some() {
        // Session affinity is meaningless without shared state; accept but log.
        tracing::debug!("session_id provided without a shared store; ignoring");
    }
    None
}

async fn load_session(
    state: &AppState,
    vault: &mut pii_core::PiiSessionVault,
    session_id: &str,
) -> Option<Response> {
    let store = state.store.as_ref().expect("checked");
    let store = Arc::clone(store);
    let sid = session_id.to_string();
    let entries = match tokio::task::spawn_blocking(move || store.get_entries(&sid)).await {
        Ok(Ok(entries)) => entries,
        Ok(Err(e)) => {
            tracing::warn!(?e, "redis session load failed");
            return Some(internal("session load failed"));
        }
        Err(_) => return Some(internal("session load task failed")),
    };

    if let Err(e) = vault.import_sealed_entries(
        entries.iter().map(|(t, v)| (t.as_str(), v.as_str())),
        session_id,
    ) {
        return Some(internal(&format!("session import failed: {e:?}")));
    }
    None
}

async fn flush_session(
    state: &AppState,
    vault: &mut pii_core::PiiSessionVault,
    session_id: &str,
) -> Option<Response> {
    let store = state.store.as_ref().expect("checked");
    let sealed = vault.seal_dirty_entries(session_id);
    if sealed.is_empty() {
        return None;
    }
    let dirty_tokens: Vec<String> = sealed.iter().map(|(t, _)| t.clone()).collect();
    let store = Arc::clone(store);
    let sid = session_id.to_string();
    let flush_result =
        match tokio::task::spawn_blocking(move || store.put_entries(&sid, sealed)).await {
            Ok(result) => result,
            Err(_) => return Some(internal("session flush task failed")),
        };
    if let Err(e) = flush_result {
        tracing::warn!(?e, "redis session flush failed");
        return Some(internal("session flush failed"));
    }
    vault.clear_dirty_tokens(&dirty_tokens);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let state = Arc::new(test_state());
        let app = router(state);
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    fn test_state() -> AppState {
        let cfg = crate::config::Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            token_format: pii_core::TokenFormat::StatelessSealed,
            seal_key: Some(zeroize::Zeroizing::new([7u8; 32])),
            redis_url: None,
            max_body_bytes: 1_048_576,
            log_format: crate::config::LogFormat::Json,
        };
        AppState::build(cfg).unwrap()
    }
}
