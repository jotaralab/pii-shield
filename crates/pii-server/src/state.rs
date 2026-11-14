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
    /// Shared scanner used to report detected entities in API responses.
    pub scanner: PiiScanner,
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
        let scanner = PiiScanner::from_catalog(&build_catalog()?)?;

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

/// Removes credentials (anything between `scheme://` and the last `@`)
/// before a connection URL may appear in logs.
pub fn redact_url(url: &str) -> String {
    match url.find("://") {
        Some(scheme_end) => match url.rfind('@') {
            Some(at) if at > scheme_end => {
                format!("{}<redacted>@{}", &url[..scheme_end + 3], &url[at + 1..])
            }
            _ => url.to_string(),
        },
        None => url.to_string(),
    }
}

fn build_catalog() -> Result<PiiCatalog, String> {
    PiiCatalog::with_locales(&["global", "us", "eu", "sg"]).map_err(|e| format!("catalog: {e:?}"))
}

/// Creates a fresh [`PiiSessionVault`] from the resolved configuration.
///
/// In `stateless-sealed` mode the session key comes from `PII_SEAL_KEY` and
/// tokens are self-contained, so a per-request vault needs no shared state.
/// In `redis` mode callers additionally load/flush entries via
/// [`PiiSessionVault::load_from_store`] / [`PiiSessionVault::flush_to_store`].
pub fn build_vault(cfg: &Config) -> Result<PiiSessionVault, String> {
    let mut vault = match &cfg.seal_key {
        Some(key) => PiiSessionVault::try_from_catalog_with_key(build_catalog()?, **key)
            .map_err(|e| format!("vault: {e}"))?,
        None => PiiSessionVault::try_from_catalog(build_catalog()?)
            .map_err(|e| format!("vault: {e}"))?,
    };
    vault.set_token_format(cfg.token_format);
    if cfg.token_format == TokenFormat::StatelessSealed {
        vault.set_stateless_mode(true);
    }
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
        assert_eq!(redact_url("plain-value"), "plain-value");
    }
}
