//! Type-erased vault store used by the proxy's inbound/outbound threads.

use pii_core::{InMemoryVaultStore, PiiVaultStore};
use pii_store_redis::{RedisVaultStore, DEFAULT_TIMEOUT};

/// Default Redis/Valkey key prefix for sealed session hashes.
pub const DEFAULT_KEY_PREFIX: &str = "pii:v1";

/// Concrete store backend selected by the proxy configuration.
///
/// Both variants share one `Error = String` so the proxy can pass a single
/// `&dyn PiiVaultStore<Error = String>` across threads regardless of backend.
#[allow(dead_code)] // `Memory` is used by unit/E2E tests and embedders.
pub enum ProxyStore {
    Memory(InMemoryVaultStore),
    Redis(Box<RedisVaultStore>),
}

impl ProxyStore {
    #[allow(dead_code)]
    pub fn memory() -> Self {
        ProxyStore::Memory(InMemoryVaultStore::new())
    }

    pub fn redis(url: &str, ttl_secs: u64) -> Result<Self, String> {
        RedisVaultStore::new(url, DEFAULT_KEY_PREFIX, ttl_secs, DEFAULT_TIMEOUT)
            .map(|s| ProxyStore::Redis(Box::new(s)))
            .map_err(|e| e.to_string())
    }
}

impl PiiVaultStore for ProxyStore {
    type Error = String;

    fn get_entries(&self, session_id: &str) -> Result<Vec<(String, String)>, Self::Error> {
        match self {
            ProxyStore::Memory(store) => store
                .get_entries(session_id)
                .map_err(|e| format!("in-memory store error: {:?}", e)),
            ProxyStore::Redis(store) => store.get_entries(session_id).map_err(|e| e.to_string()),
        }
    }

    fn put_entries(
        &self,
        session_id: &str,
        entries: Vec<(String, String)>,
    ) -> Result<(), Self::Error> {
        match self {
            ProxyStore::Memory(store) => store
                .put_entries(session_id, entries)
                .map_err(|e| format!("in-memory store error: {:?}", e)),
            ProxyStore::Redis(store) => store
                .put_entries(session_id, entries)
                .map_err(|e| e.to_string()),
        }
    }
}
