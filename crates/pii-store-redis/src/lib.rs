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

/// Default connection/read/write timeout for a single command round-trip.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

/// Persistent Valkey/Redis connection implementing [`PiiVaultStore`].
///
/// The socket is cached behind a `Mutex<Option<Connection>>` and transparently
/// re-established when the server closes it, so the proxy never opens a new
/// TCP/TLS connection per MCP message.
pub struct RedisVaultStore {
    client: redis::Client,
    key_prefix: String,
    ttl_secs: u64,
    timeout: Duration,
    conn: Mutex<Option<Connection>>,
}

impl RedisVaultStore {
    /// Creates the adapter. `redis_url` may be `redis://`, `rediss://`, or a
    /// unix-socket URL understood by the `redis` crate.
    pub fn new(
        redis_url: &str,
        key_prefix: impl Into<String>,
        ttl_secs: u64,
        timeout: Duration,
    ) -> Result<Self, RedisStoreError> {
        let key_prefix = key_prefix.into();
        if key_prefix.trim().is_empty() {
            return Err(RedisStoreError::Configuration(
                "key prefix must be non-empty".to_string(),
            ));
        }
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

    fn connect(&self) -> Result<Connection, RedisStoreError> {
        let conn = self.client.get_connection()?;
        // Explicit read/write timeouts keep a black-holed server from blocking
        // an MCP turn indefinitely.
        conn.set_read_timeout(Some(self.timeout))?;
        conn.set_write_timeout(Some(self.timeout))?;
        Ok(conn)
    }

    /// Runs `op` against the cached connection, reconnecting once if the
    /// server closed the socket (idle timeout, restart, failover).
    fn with_connection<T>(
        &self,
        op: impl Fn(&mut Connection) -> Result<T, RedisError>,
    ) -> Result<T, RedisStoreError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| RedisStoreError::Configuration("connection mutex poisoned".into()))?;

        if guard.is_none() {
            *guard = Some(self.connect()?);
        }

        let first = {
            let conn = guard.as_mut().expect("connection initialized above");
            op(conn)
        };
        match first {
            Ok(v) => Ok(v),
            Err(err) if is_reconnectable(&err) => {
                // Drop the dead socket and retry exactly once on a fresh one.
                *guard = None;
                let mut conn = self.connect()?;
                let retried = op(&mut conn);
                *guard = Some(conn);
                retried.map_err(RedisStoreError::Redis)
            }
            Err(err) => Err(RedisStoreError::Redis(err)),
        }
    }
}

fn is_reconnectable(err: &RedisError) -> bool {
    err.is_connection_dropped() || err.is_io_error() || err.is_timeout()
}

impl PiiVaultStore for RedisVaultStore {
    type Error = RedisStoreError;

    fn get_entries(&self, session_id: &str) -> Result<Vec<(String, String)>, Self::Error> {
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
        let key = self.session_key(session_id);
        let ttl = self.ttl_secs;
        self.with_connection(|conn| {
            redis::pipe()
                .atomic()
                .hset_multiple(&key, &entries)
                .ignore()
                .expire(&key, ttl as i64)
                .ignore()
                .query(conn)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    /// Minimal RESP server state shared with the test thread.
    #[derive(Default)]
    struct RespState {
        /// session key -> field/value pairs
        hashes: HashMap<String, HashMap<String, String>>,
        /// session key -> last EXPIRE ttl
        ttls: HashMap<String, i64>,
        /// Commands observed, in order (lowercased, first token only).
        commands: Vec<String>,
        /// Number of connections accepted.
        connections: usize,
    }

    struct RespServer {
        addr: String,
        state: Arc<StdMutex<RespState>>,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl RespServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RESP server");
            let addr = listener.local_addr().unwrap().to_string();
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let state = Arc::new(StdMutex::new(RespState::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let state_t = Arc::clone(&state);
            let stop_t = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !stop_t.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            state_t.lock().unwrap().connections += 1;
                            let state_c = Arc::clone(&state_t);
                            thread::spawn(move || handle_client(stream, state_c));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                state,
                stop,
                handle: Some(handle),
            }
        }

        fn url(&self) -> String {
            format!("redis://{}", self.addr)
        }
    }

    impl Drop for RespServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn read_resp_arg(reader: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.starts_with('*') {
            return Some(Vec::new());
        }
        let count: usize = line[1..].parse().ok()?;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_line = String::new();
            reader.read_line(&mut len_line).ok()?;
            let len_line = len_line.trim_end_matches(['\r', '\n']);
            let len: usize = len_line.strip_prefix('$')?.parse().ok()?;
            let mut buf = vec![0u8; len + 2];
            use std::io::Read;
            reader.read_exact(&mut buf).ok()?;
            args.push(String::from_utf8_lossy(&buf[..len]).to_string());
        }
        Some(args)
    }

    fn handle_client(stream: TcpStream, state: Arc<StdMutex<RespState>>) {
        let mut writer = stream.try_clone().expect("clone stream");
        let mut reader = BufReader::new(stream);
        let mut queued: Vec<Vec<String>> = Vec::new();
        let mut in_multi = false;
        while let Some(args) = read_resp_arg(&mut reader) {
            if args.is_empty() {
                continue;
            }
            let cmd = args[0].to_ascii_lowercase();
            {
                let mut st = state.lock().unwrap();
                st.commands.push(cmd.clone());
            }
            if in_multi {
                match cmd.as_str() {
                    "exec" => {
                        let mut replies = Vec::new();
                        for q in queued.drain(..) {
                            replies.push(apply_command(&q, &state));
                        }
                        write_array(&mut writer, &replies);
                        in_multi = false;
                    }
                    "discard" => {
                        queued.clear();
                        in_multi = false;
                        let _ = writer.write_all(b"+OK\r\n");
                    }
                    _ => {
                        queued.push(args);
                        let _ = writer.write_all(b"+QUEUED\r\n");
                    }
                }
                continue;
            }
            if cmd == "multi" {
                in_multi = true;
                let _ = writer.write_all(b"+OK\r\n");
                continue;
            }
            let reply = apply_command(&args, &state);
            let _ = writer.write_all(&reply);
        }
    }

    fn apply_command(args: &[String], state: &Arc<StdMutex<RespState>>) -> Vec<u8> {
        let cmd = args[0].to_ascii_lowercase();
        let mut st = state.lock().unwrap();
        match cmd.as_str() {
            "hgetall" => {
                let map = st.hashes.get(&args[1]).cloned().unwrap_or_default();
                let mut out = format!("*{}\r\n", map.len() * 2).into_bytes();
                for (k, v) in map {
                    out.extend_from_slice(format!("${}\r\n{}\r\n", k.len(), k).as_bytes());
                    out.extend_from_slice(format!("${}\r\n{}\r\n", v.len(), v).as_bytes());
                }
                out
            }
            "hset" | "hmset" => {
                let map = st.hashes.entry(args[1].clone()).or_default();
                let mut added = 0;
                let mut i = 2;
                while i + 1 < args.len() {
                    if map.insert(args[i].clone(), args[i + 1].clone()).is_none() {
                        added += 1;
                    }
                    i += 2;
                }
                format!(":{}\r\n", added).into_bytes()
            }
            "expire" => {
                let ttl = args[2].parse::<i64>().unwrap_or(-1);
                st.ttls.insert(args[1].clone(), ttl);
                b":1\r\n".to_vec()
            }
            "ping" => b"+PONG\r\n".to_vec(),
            _ => b"+OK\r\n".to_vec(),
        }
    }

    fn write_array(writer: &mut TcpStream, replies: &[Vec<u8>]) {
        let mut out = format!("*{}\r\n", replies.len()).into_bytes();
        for r in replies {
            out.extend_from_slice(r);
        }
        let _ = writer.write_all(&out);
    }

    fn store(server: &RespServer) -> RedisVaultStore {
        RedisVaultStore::new(&server.url(), "pii:v1", 3600, Duration::from_millis(500))
            .expect("construct store")
    }

    #[test]
    fn test_put_entries_atomic_hset_and_expire() {
        let server = RespServer::start();
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

        let st = server.state.lock().unwrap();
        assert_eq!(st.hashes["pii:v1:sess-1"].len(), 2);
        assert_eq!(st.ttls["pii:v1:sess-1"], 3600);
        assert!(st.commands.iter().any(|c| c == "multi"));
        assert!(st.commands.iter().any(|c| c == "exec"));
    }

    #[test]
    fn test_get_entries_roundtrip() {
        let server = RespServer::start();
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
    fn test_reconnects_after_server_closes_socket() {
        // First connection: read one command and close without replying (a
        // server restart / idle-timeout eviction). Second connection: serve
        // the retried HGETALL. The adapter must transparently reconnect.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connections = Arc::new(StdMutex::new(0usize));
        let connections_t = Arc::clone(&connections);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut count = 0usize;
            while !stop_t.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        count += 1;
                        *connections_t.lock().unwrap() = count;
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        while let Some(args) = read_resp_arg(&mut reader) {
                            let cmd = args[0].to_ascii_lowercase();
                            if cmd == "client" {
                                // Connection handshake (CLIENT SETINFO).
                                let _ = stream.write_all(b"+OK\r\n");
                                continue;
                            }
                            if count == 1 {
                                // Drop the socket mid-operation, no reply.
                                break;
                            }
                            // HGETALL reply: one field/value pair.
                            let _ = stream.write_all(b"*2\r\n$8\r\n<ID_NIK>\r\n$8\r\nPIIS1:AA\r\n");
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let store = RedisVaultStore::new(
            &format!("redis://{}", addr),
            "pii:v1",
            60,
            Duration::from_millis(500),
        )
        .unwrap();

        let entries = store.get_entries("s").expect("retry after dropped socket");
        assert_eq!(
            entries,
            vec![("<ID_NIK>".to_string(), "PIIS1:AA".to_string())]
        );
        assert_eq!(*connections.lock().unwrap(), 2, "must reconnect once");

        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();
    }

    #[test]
    fn test_rejects_invalid_configuration() {
        assert!(RedisVaultStore::new("redis://127.0.0.1:1", "", 60, DEFAULT_TIMEOUT).is_err());
        assert!(RedisVaultStore::new("redis://127.0.0.1:1", "pii", 0, DEFAULT_TIMEOUT).is_err());
        assert!(
            RedisVaultStore::new("redis://127.0.0.1:1", "pii", 60, Duration::from_millis(0))
                .is_err()
        );
    }
}
