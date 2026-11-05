//! Minimal in-process RESP (Redis/Valkey) server used by unit and E2E tests.
//!
//! Supports the commands the adapter emits: `HGETALL`, `HSET`/`HMSET`,
//! `EXPIRE`, `MULTI`/`EXEC`, and the `CLIENT SETINFO` handshake. Fault
//! injection covers dropped sockets, aborted `EXEC`, and `EXPIRE` failures.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Shared server state, inspectable from tests.
#[derive(Default)]
pub struct MockState {
    pub hashes: HashMap<String, HashMap<String, String>>,
    pub ttls: HashMap<String, i64>,
    /// Commands observed, lowercased first token, in order.
    pub commands: Vec<String>,
    pub connections: usize,
    pub execs: usize,
}

struct Faults {
    /// Close the listener + socket after replying to the first `HGETALL`.
    keep_serving: bool,
    /// Drop this numbered real (non-handshake) command without replying.
    drop_op_number: Option<usize>,
    /// Reply `-ERR` to the first `EXEC` (transaction abort).
    fail_first_exec: bool,
    /// Return `:0` from `EXPIRE` (no TTL applied).
    expire_failure: bool,
}

/// In-process RESP server. Creates a fresh ephemeral port per instance.
pub struct MockValkey {
    addr: String,
    state: Arc<Mutex<MockState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockValkey {
    /// Happy-path server that keeps serving all connections.
    pub fn start() -> Self {
        Self::spawn(Faults {
            keep_serving: true,
            drop_op_number: None,
            fail_first_exec: false,
            expire_failure: false,
        })
    }

    /// Serves the startup `HGETALL`, then shuts down to simulate an outage.
    pub fn start_with(keep_serving: bool) -> Self {
        Self::spawn(Faults {
            keep_serving,
            drop_op_number: None,
            fail_first_exec: false,
            expire_failure: false,
        })
    }

    /// Drops the second real command on each connection without a reply.
    /// The first `HGETALL` establishes a cached socket, then the next call on
    /// that socket is evicted and must reconnect.
    pub fn start_dropping_second_operation() -> Self {
        Self::spawn(Faults {
            keep_serving: true,
            drop_op_number: Some(2),
            fail_first_exec: false,
            expire_failure: false,
        })
    }

    /// Aborts the first atomic `EXEC`, then succeeds.
    pub fn start_failing_first_exec() -> Self {
        Self::spawn(Faults {
            keep_serving: true,
            drop_op_number: None,
            fail_first_exec: true,
            expire_failure: false,
        })
    }

    /// Returns `:0` for every `EXPIRE` (TTL never applied).
    pub fn start_with_expire_failure() -> Self {
        Self::spawn(Faults {
            keep_serving: true,
            drop_op_number: None,
            fail_first_exec: false,
            expire_failure: true,
        })
    }

    fn spawn(faults: Faults) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock valkey");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(MockState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let state_t = Arc::clone(&state);
        let stop_t = Arc::clone(&stop);
        let faults = Arc::new(faults);
        let handle = thread::spawn(move || {
            let mut active: Vec<TcpStream> = Vec::new();
            while !stop_t.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Accepted sockets may inherit O_NONBLOCK on BSD/macOS.
                        stream
                            .set_nonblocking(false)
                            .expect("blocking client stream");
                        let state_c = Arc::clone(&state_t);
                        let stop_c = Arc::clone(&stop_t);
                        let faults_c = Arc::clone(&faults);
                        let ctl = stream.try_clone().unwrap();
                        active.push(ctl);
                        thread::spawn(move || {
                            handle_client(stream, state_c, stop_c, faults_c);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for s in active {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        Self {
            addr,
            state,
            stop,
            handle: Some(handle),
        }
    }

    pub fn url(&self) -> String {
        format!("redis://{}", self.addr)
    }

    pub fn entry_count(&self, key: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .hashes
            .get(key)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    pub fn has_field(&self, key: &str, field: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .hashes
            .get(key)
            .is_some_and(|m| m.contains_key(field))
    }

    pub fn ttl(&self, key: &str) -> Option<i64> {
        self.state.lock().unwrap().ttls.get(key).copied()
    }

    pub fn command_count(&self, command: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .commands
            .iter()
            .filter(|c| c.as_str() == command)
            .count()
    }

    pub fn connections(&self) -> usize {
        self.state.lock().unwrap().connections
    }
}

impl Drop for MockValkey {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn read_args(reader: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
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
        reader.read_exact(&mut buf).ok()?;
        args.push(String::from_utf8_lossy(&buf[..len]).to_string());
    }
    Some(args)
}

fn handle_client(
    stream: TcpStream,
    state: Arc<Mutex<MockState>>,
    stop: Arc<AtomicBool>,
    faults: Arc<Faults>,
) {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut queued: Vec<Vec<String>> = Vec::new();
    let mut in_multi = false;
    let mut real_ops = 0usize;
    {
        let mut st = state.lock().unwrap();
        st.connections += 1;
    }

    while let Some(args) = read_args(&mut reader) {
        if args.is_empty() {
            continue;
        }
        let cmd = args[0].to_ascii_lowercase();
        state.lock().unwrap().commands.push(cmd.clone());

        if cmd == "client" {
            let _ = writer.write_all(b"+OK\r\n");
            continue;
        }

        real_ops += 1;
        if faults.drop_op_number == Some(real_ops) {
            // Close without replying so the adapter must reconnect.
            let _ = writer.shutdown(std::net::Shutdown::Both);
            let _ = reader.get_ref().shutdown(std::net::Shutdown::Both);
            break;
        }

        if in_multi {
            match cmd.as_str() {
                "exec" => {
                    in_multi = false;
                    let fail_exec = {
                        let mut st = state.lock().unwrap();
                        st.execs += 1;
                        faults.fail_first_exec && st.execs == 1
                    };
                    if fail_exec {
                        queued.clear();
                        let _ = writer.write_all(b"-ERR mock transient failure\r\n");
                        continue;
                    }
                    let replies: Vec<Vec<u8>> = queued
                        .drain(..)
                        .map(|q| apply(&q, &state, &faults))
                        .collect();
                    write_array(&mut writer, &replies);
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

        let reply = apply(&args, &state, &faults);
        let _ = writer.write_all(&reply);

        if cmd == "hgetall" && !faults.keep_serving {
            stop.store(true, Ordering::SeqCst);
            let _ = writer.shutdown(std::net::Shutdown::Both);
            let _ = reader.get_ref().shutdown(std::net::Shutdown::Both);
            break;
        }
    }
}

fn apply(args: &[String], state: &Arc<Mutex<MockState>>, faults: &Faults) -> Vec<u8> {
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
            if faults.expire_failure {
                b":0\r\n".to_vec()
            } else {
                b":1\r\n".to_vec()
            }
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
