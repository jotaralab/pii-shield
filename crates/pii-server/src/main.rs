//! `pii-server` entrypoint: HTTP/JSON + MCP Streamable HTTP server for
//! pii-shield, designed for Kubernetes (standalone or sidecar).

use pii_server::config::{self, Config};
use std::sync::Arc;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

fn init_tracing(cfg: &Config) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pii_server=info"));
    let registry = tracing_subscriber::registry().with(filter);
    match cfg.log_format {
        config::LogFormat::Json => registry.with(fmt::layer().json()).init(),
        config::LogFormat::Pretty => registry.with(fmt::layer()).init(),
    }
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    if let Err(code) = runtime.block_on(run()) {
        eprintln!("pii-server: fatal: {code}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Fail fast on bad configuration before touching the network.
    let cfg = Config::from_env().map_err(|e| e.to_string())?;
    init_tracing(&cfg);

    tracing::info!(bind = %cfg.bind_addr, ?cfg.token_format, "starting pii-server");

    let state = Arc::new(pii_server::state::AppState::build(cfg.clone())?);

    let app = pii_server::api::router(Arc::clone(&state))
        .merge(pii_server::mcp::router(Arc::clone(&state)))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            std::time::Duration::from_secs(30),
        ));

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", cfg.bind_addr))?;

    tracing::info!(addr = %cfg.bind_addr, "pii-server listening");

    // Graceful shutdown on SIGTERM (Kubernetes) or SIGINT.
    let shutdown_tx = state.shutdown_tx.clone();
    let shutdown = async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let sigint = tokio::signal::ctrl_c();
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received; draining"),
            _ = sigint => tracing::info!("SIGINT received; draining"),
        }
        // Signal long-lived SSE streams so graceful shutdown can complete.
        let _ = shutdown_tx.send(true);
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| format!("server error: {e}"))?;

    tracing::info!("pii-server shut down cleanly");
    Ok(())
}
