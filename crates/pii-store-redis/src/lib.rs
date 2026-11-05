//! Valkey / Redis backed [`PiiVaultStore`] adapter.
//!
//! Each session is stored as a single Redis hash:
//!
//! ```text
//! {key_prefix}:{session_id} = {
//!     "<ID_NIK_K9X4M2>": "<SIV-sealed hex blob bound to session_id>",
//!     ...
//! }
//! ```
//!
//! Every session hash carries a TTL. `put_entries` uses a single atomic
//! `MULTI`/`HSET`/`EXPIRE`/`EXEC` pipeline so concurrent pods merge fields
//! without clobbering each other.

use pii_core::PiiVaultStore;
use redis::{Commands, Connection, RedisError};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Errors surfaced by [`RedisVaultStore`].
#[derive(Debug)]
pub enum RedisStoreError {
    /// The Redis/Valkey server could not be reached or rejected the command.
    Redis(RedisError),
    /// The configured URL, key prefix, or TTL is invalid.
    Configuration(String),
}

impl fmt::Display for RedisStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedisStoreError::Redis(e) => write!(f, "redis store error: {}", e),
            RedisStoreError::Configuration(msg) => write!(f, "redis store config error: {}", msg),
        }
    }
}

impl std::error::Error for RedisStoreError {}

impl From<RedisError> for RedisStoreError {
    fn from(e: RedisError) -> Self {
        RedisStoreError::Redis(e)
    }
}

/// Default connect/read/write timeout for a single command round-trip.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

/// Persistent Valkey/Redis connection implementing [`PiiVaultStore`].
///
/// The socket is cached behind a `Mutex<Option<Connection>>` and transparently
/// re-established when the server closes it, so the proxy never opens a new
/// TCP/TLS connection per MCP message.
pub struct RedisVaultStore {
    client: redis::Client,
    key_prefix: String,
    /// Validated to fit in `i64`: Redis `EXPIRE` with a negative value would
    /// delete the session hash immediately.
    ttl_secs: i64,
    timeout: Duration,
    conn: Mutex<Option<Connection>>,
}

impl RedisVaultStore {
    /// Creates the adapter. `redis_url` may be `redis://`, `rediss://` (when
    /// the `redis` crate is built with a TLS feature), or a unix-socket URL
    /// understood by the `redis` crate.
    pub fn new(
        redis_url: &str,
        key_prefix: impl Into<String>,
        ttl_secs: u64,
        timeout: Duration,
    ) -> Result<Self, RedisStoreError> {
        let key_prefix = key_prefix.into().trim().to_string();
        if key_prefix.is_empty() {
            return Err(RedisStoreError::Configuration(
                "key prefix must be non-empty".to_string(),
            ));
        }
        let ttl_secs = i64::try_from(ttl_secs).map_err(|_| {
            RedisStoreError::Configuration(format!(
                "session TTL must be between 1 and {} seconds",
                i64::MAX
            ))
        })?;
        if ttl_secs == 0 {
            return Err(RedisStoreError::Configuration(
                "session TTL must be greater than zero".to_string(),
            ));
        }
        if timeout.is_zero() {
            return Err(RedisStoreError::Configuration(
                "timeout must be greater than zero".to_string(),
            ));
        }
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            key_prefix,
            ttl_secs,
            timeout,
            conn: Mutex::new(None),
        })
    }

    /// Convenience constructor using [`DEFAULT_TIMEOUT`].
    pub fn with_default_timeout(
        redis_url: &str,
        key_prefix: impl Into<String>,
        ttl_secs: u64,
    ) -> Result<Self, RedisStoreError> {
        Self::new(redis_url, key_prefix, ttl_secs, DEFAULT_TIMEOUT)
    }

    /// Returns the fully-qualified Redis hash key for a session.
    pub fn session_key(&self, session_id: &str) -> String {
        format!("{}:{}", self.key_prefix, session_id)
    }

    fn validate_session_id(session_id: &str) -> Result<(), RedisStoreError> {
        if session_id.trim().is_empty() {
            return Err(RedisStoreError::Configuration(
                "session id must be non-empty".to_string(),
            ));
        }
        Ok(())
    }

    fn connect(&self) -> Result<Connection, RedisStoreError> {
        // A connect timeout is required: a black-holed host would otherwise
        // block for the OS TCP SYN retransmit window (~60-120s).
        let conn = self.client.get_connection_with_timeout(self.timeout)?;
        conn.set_read_timeout(Some(self.timeout))?;
        conn.set_write_timeout(Some(self.timeout))?;
        Ok(conn)
    }

    /// Runs `op` against the cached connection.
    ///
    /// A stale pooled socket (dropped by the server during idle/failover) is
    /// retried exactly once on a fresh connection. Any failed command evicts
    /// the connection so a half-written `MULTI` transaction or an unconsumed
    /// RESP frame can never leak into the next session's request.
    fn with_connection<T>(
        &self,
        op: impl Fn(&mut Connection) -> Result<T, RedisError>,
    ) -> Result<T, RedisStoreError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| RedisStoreError::Configuration("connection mutex poisoned".into()))?;

        let was_cached = guard.is_some();
        if !was_cached {
            *guard = Some(self.connect()?);
        }

        let first = {
            let conn = guard.as_mut().expect("connection initialized above");
            op(conn)
        };
        match first {
            Ok(v) => Ok(v),
            Err(err) if was_cached && is_reconnectable(&err) => {
                // Drop the stale pooled socket and retry once on a fresh one.
                *guard = None;
                let mut conn = self.connect()?;
                match op(&mut conn) {
                    Ok(v) => {
                        *guard = Some(conn);
                        Ok(v)
                    }
                    Err(retry_err) => Err(RedisStoreError::Redis(retry_err)),
                }
            }
            Err(err) => {
                // Never cache a connection that just failed.
                *guard = None;
                Err(RedisStoreError::Redis(err))
            }
        }
    }
}

/// Only retry sockets the server closed. A read/write timeout is *not*
/// retried: a stalled pipeline already consumed up to `4 × timeout`, and a
/// retry would double the MCP turn latency for no benefit.
fn is_reconnectable(err: &RedisError) -> bool {
    err.is_connection_dropped() || (err.is_io_error() && !err.is_timeout())
}

impl PiiVaultStore for RedisVaultStore {
    type Error = RedisStoreError;

    fn get_entries(&self, session_id: &str) -> Result<Vec<(String, String)>, Self::Error> {
        Self::validate_session_id(session_id)?;
        let key = self.session_key(session_id);
        let map: HashMap<String, String> = self.with_connection(|conn| conn.hgetall(&key))?;
        Ok(map.into_iter().collect())
    }

    fn put_entries(
        &self,
        session_id: &str,
        entries: Vec<(String, String)>,
    ) -> Result<(), Self::Error> {
        if entries.is_empty() {
            return Ok(());
        }
        Self::validate_session_id(session_id)?;
        let key = self.session_key(session_id);
        let ttl = self.ttl_secs;
        self.with_connection(|conn| {
            let (_added, expire_rc): (i64, i64) = redis::pipe()
                .atomic()
                .hset_multiple(&key, &entries)
                .expire(&key, ttl)
                .query(conn)?;
            // `EXEC` aborted (`Nil`) deserializes to an empty tuple / 0; and
            // `EXPIRE` returning 0 means no TTL was applied. Both would let a
            // caller clear dirty tokens for data that was never persisted.
            if expire_rc != 1 {
                return Err(RedisError::from((
                    redis::ErrorKind::ResponseError,
                    "EXPIRE failed to set TTL on session hash",
                )));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockValkey;
    use super::*;

    fn store(server: &MockValkey) -> RedisVaultStore {
        RedisVaultStore::new(&server.url(), "pii:v1", 3600, Duration::from_millis(500))
            .expect("construct store")
    }

    #[test]
    fn test_put_entries_atomic_hset_and_expire() {
        let server = MockValkey::start();
        let store = store(&server);
        store
            .put_entries(
                "sess-1",
                vec![
                    ("<ID_NIK_A>".to_string(), "PIIS1:AA".to_string()),
                    ("<ID_NIK_B>".to_string(), "PIIS1:BB".to_string()),
                ],
            )
            .expect("put succeeds");

        assert_eq!(server.entry_count("pii:v1:sess-1"), 2);
        assert_eq!(server.ttl("pii:v1:sess-1"), Some(3600));
        assert!(server.command_count("multi") >= 1);
        assert!(server.command_count("exec") >= 1);
        assert!(
            server.command_count("hset") + server.command_count("hmset") >= 1,
            "HSET/HMSET must be issued"
        );
    }

    #[test]
    fn test_get_entries_roundtrip() {
        let server = MockValkey::start();
        let store = store(&server);
        store
            .put_entries(
                "sess-2",
                vec![("<ID_NIK_X>".to_string(), "PIIS1:DEAD".to_string())],
            )
            .unwrap();

        let mut entries = store.get_entries("sess-2").unwrap();
        entries.sort();
        assert_eq!(
            entries,
            vec![("<ID_NIK_X>".to_string(), "PIIS1:DEAD".to_string())]
        );
        assert!(store.get_entries("missing").unwrap().is_empty());
    }

    #[test]
    fn test_rejects_empty_session_id() {
        let server = MockValkey::start();
        let store = store(&server);
        assert!(store.get_entries("").is_err());
        assert!(store.get_entries("   ").is_err());
        assert!(store
            .put_entries(" ", vec![("a".into(), "b".into())])
            .is_err());
    }

    #[test]
    fn test_reconnects_after_server_closes_socket() {
        // First connection drops the first real command without replying
        // (server restart / idle eviction); the retry must succeed.
        let server = MockValkey::start_dropping_second_operation();
        let store = store(&server);
        // First call establishes the cached socket.
        assert!(store.get_entries("s").unwrap().is_empty());
        // Second call on the same socket is dropped by the server; the adapter
        // must evict it and transparently retry on a fresh connection.
        assert!(store
            .get_entries("s")
            .expect("retry after dropped socket")
            .is_empty());
        assert_eq!(server.connections(), 2, "must reconnect once");
    }

    #[test]
    fn test_first_attempt_failure_is_not_cached() {
        // A brand-new connection that fails must be evicted; the next call
        // reconnects instead of reusing a desynchronized socket.
        let server = MockValkey::start_failing_first_exec();
        let store = store(&server);
        assert!(store
            .put_entries("s", vec![("a".into(), "b".into())])
            .is_err());

        // Next write uses a fresh connection and succeeds.
        store
            .put_entries("s", vec![("a".into(), "b".into())])
            .expect("retry succeeds");
        assert_eq!(server.entry_count("pii:v1:s"), 1);
    }

    #[test]
    fn test_failed_expire_returns_error() {
        let server = MockValkey::start_with_expire_failure();
        let store = store(&server);
        // EXPIRE returns 0, so the write must not be reported as successful.
        assert!(store
            .put_entries("s", vec![("a".into(), "b".into())])
            .is_err());
    }

    #[test]
    fn test_rejects_invalid_configuration() {
        assert!(RedisVaultStore::new("redis://127.0.0.1:1", "", 60, DEFAULT_TIMEOUT).is_err());
        assert!(RedisVaultStore::new("redis://127.0.0.1:1", "pii", 0, DEFAULT_TIMEOUT).is_err());
        assert!(
            RedisVaultStore::new("redis://127.0.0.1:1", "pii", u64::MAX, DEFAULT_TIMEOUT).is_err()
        );
        assert!(
            RedisVaultStore::new("redis://127.0.0.1:1", "pii", 60, Duration::from_millis(0))
                .is_err()
        );
        // Prefixes are trimmed before use.
        let ok = RedisVaultStore::new("redis://127.0.0.1:1", " pii ", 60, DEFAULT_TIMEOUT).unwrap();
        assert_eq!(ok.session_key("s"), "pii:s");
    }
}
