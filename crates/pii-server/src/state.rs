//! Shared application state and vault/session management.

use crate::config::Config;
use metrics_exporter_prometheus::PrometheusHandle;
use pii_core::{PiiCatalog, PiiScanner, PiiSessionVault, TokenFormat};
use pii_store_redis::RedisVaultStore;
use std::sync::Arc;
use tokio::sync::watch;

/// Immutable state shared by all handlers.
pub struct AppState {
    pub cfg: Arc<Config>,
    /// Shared pre-compiled scanner reused across all per-request vaults in O(1).
    pub scanner: Arc<PiiScanner>,
    /// Optional Redis-backed vault store (token format `redis`).
    pub store: Option<Arc<RedisVaultStore>>,
    /// Prometheus registry handle for `GET /metrics`.
    pub prometheus: PrometheusHandle,
    /// Fired when the process is shutting down; long-lived SSE streams
    /// observe this so graceful shutdown can complete promptly.
    pub shutdown: watch::Receiver<bool>,
    /// Sender half of the shutdown signal, wired to the signal handler.
    pub shutdown_tx: watch::Sender<bool>,
}

impl AppState {
    /// Builds the application state, failing fast on any invalid setup.
    pub fn build(cfg: Config) -> Result<Self, String> {
        let locale_refs: Vec<&str> = cfg.locales.iter().map(String::as_str).collect();
        let catalog =
            PiiCatalog::with_locales(&locale_refs).map_err(|e| format!("catalog: {e:?}"))?;
        let scanner = Arc::new(PiiScanner::from_catalog(&catalog)?);

        let store = match &cfg.redis_url {
            Some(url) => {
                tracing::info!(url = %redact_url(url), "initializing redis vault store");
                Some(Arc::new(
                    RedisVaultStore::with_default_timeout(url, "pii:v1", 3600)
                        .map_err(|e| format!("failed to initialize redis store: {e:?}"))?,
                ))
            }
            None => None,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(AppState {
            cfg: Arc::new(cfg),
            scanner,
            store,
            prometheus: crate::metrics::install(),
            shutdown: shutdown_rx,
            shutdown_tx,
        })
    }
}

/// Removes credentials (anything between `scheme://` and the last `@`, as well
/// as `password=...` query parameters) before a connection URL may appear in logs.
pub fn redact_url(url: &str) -> String {
    let mut sanitized = match url.find("://") {
        Some(scheme_end) => match url.rfind('@') {
            Some(at) if at > scheme_end => {
                format!("{}<redacted>@{}", &url[..scheme_end + 3], &url[at + 1..])
            }
            _ => url.to_string(),
        },
        None => return "<redacted-url>".to_string(),
    };
    if let Some(q_idx) = sanitized.find('?') {
        let base = sanitized[..q_idx].to_string();
        let query = &sanitized[q_idx + 1..];
        let masked_params: Vec<String> = query
            .split('&')
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let k = parts.next().unwrap_or("");
                if k.eq_ignore_ascii_case("password") || k.eq_ignore_ascii_case("auth") {
                    format!("{k}=<redacted>")
                } else {
                    pair.to_string()
                }
            })
            .collect();
        sanitized = format!("{base}?{}", masked_params.join("&"));
    }
    sanitized
}

/// Creates a fresh [`PiiSessionVault`] from `AppState` in O(1) time by
/// sharing the pre-compiled [`PiiScanner`].
pub fn build_vault(state: &AppState, session_id: Option<&str>) -> Result<PiiSessionVault, String> {
    let key = state
        .cfg
        .seal_key
        .as_ref()
        .ok_or_else(|| "PII_SEAL_KEY is not configured".to_string())?;
    let mut vault = PiiSessionVault::from_shared_scanner_with_key(
        Arc::clone(&state.scanner),
        **key,
        pii_core::SecurityPolicy::StandardGlobal,
    );
    vault.set_token_format(state.cfg.token_format);
    if state.cfg.token_format == TokenFormat::StatelessSealed {
        vault.set_stateless_mode(true);
    }
    vault.set_aad_scope(session_id.map(str::to_string));
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_hides_credentials() {
        assert_eq!(
            redact_url("redis://:s3cret@redis:6379"),
            "redis://<redacted>@redis:6379"
        );
        assert_eq!(
            redact_url("rediss://user:pass@host:6380/2"),
            "rediss://<redacted>@host:6380/2"
        );
        assert_eq!(redact_url("redis://redis:6379"), "redis://redis:6379");
        assert_eq!(
            redact_url("redis://redis:6379?password=secret&db=0"),
            "redis://redis:6379?password=<redacted>&db=0"
        );
        assert_eq!(redact_url("plain-value"), "<redacted-url>");
    }
}
