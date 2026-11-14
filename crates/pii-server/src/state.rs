//! Shared application state and vault/session management.

use crate::config::Config;
use metrics_exporter_prometheus::PrometheusHandle;
use pii_core::{PiiCatalog, PiiScanner, PiiSessionVault, TokenFormat};
use pii_store_redis::RedisVaultStore;
use std::sync::Arc;

/// Immutable state shared by all handlers.
pub struct AppState {
    pub cfg: Arc<Config>,
    /// Shared scanner used to report detected entities in API responses.
    pub scanner: PiiScanner,
    /// Optional Redis-backed vault store (token format `redis`).
    pub store: Option<Arc<RedisVaultStore>>,
    /// Prometheus registry handle for `GET /metrics`.
    pub prometheus: PrometheusHandle,
}

impl AppState {
    /// Builds the application state, failing fast on any invalid setup.
    pub fn build(cfg: Config) -> Result<Self, String> {
        let scanner = PiiScanner::from_catalog(&build_catalog()?)?;

        let store = match &cfg.redis_url {
            Some(url) => {
                tracing::info!(%url, "initializing redis vault store");
                Some(Arc::new(
                    RedisVaultStore::with_default_timeout(url, "pii:v1", 3600)
                        .map_err(|e| format!("failed to initialize redis store: {e:?}"))?,
                ))
            }
            None => None,
        };

        Ok(AppState {
            cfg: Arc::new(cfg),
            scanner,
            store,
            prometheus: crate::metrics::install(),
        })
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
