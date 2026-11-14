use pii_core::{
    PiiCatalog, PiiSessionVault, PiiVaultStore, SecurityError, TokenFormat, ToolTrustLevel,
};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod store;
use store::ProxyStore;

pub struct ToolAcl {
    trusted_tools: HashSet<String>,
    trust_all: bool,
}

impl ToolAcl {
    pub fn new(trusted: Vec<String>, trust_all: bool) -> Self {
        Self {
            trusted_tools: trusted.into_iter().collect(),
            trust_all,
        }
    }

    pub fn get_trust_level(&self, tool_name: &str) -> ToolTrustLevel {
        if self.trust_all || self.trusted_tools.contains(tool_name) {
            ToolTrustLevel::InternalTrusted
        } else {
            ToolTrustLevel::ExternalUntrusted
        }
    }
}

#[derive(Debug)]
pub enum InboundAction {
    Forward(String),
    BlockWithError(String),
    /// Malformed JSON inbound: fail closed with a JSON-RPC parse error.
    BlockParseError,
    /// Blocked notification (no `id`): dropped without a response.
    Drop,
    /// Blocked batch: per-element error responses go to the host (stdout)
    /// while any allowed elements are still forwarded to the child.
    BatchSplit {
        to_child: Option<String>,
        to_host: String,
    },
}

/// Maximum inbound/outbound line size enforced by the proxy (16 MiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Reads one newline-terminated line from `reader` without ever allocating
/// more than `max_bytes` bytes (OOM-DoS guard for hostile stdin/stdout).
///
/// Returns `Ok(None)` at EOF with no pending bytes. If the line exceeds
/// `max_bytes`, the remainder (through the next newline) is consumed and
/// discarded — never buffered — and an error is returned so callers can fail
/// closed.
pub fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let available = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            // EOF: flush any final unterminated line.
            if buf.is_empty() {
                return Ok(None);
            }
            let s = String::from_utf8_lossy(&buf);
            return Ok(Some(s.into_owned()));
        }
        let newline = available.iter().position(|&b| b == b'\n');
        match newline {
            Some(idx) => {
                let take = idx + 1;
                if buf.len() + take > max_bytes {
                    reader.consume(take);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line exceeds --max-line-bytes ({} bytes)", max_bytes),
                    ));
                }
                buf.extend_from_slice(&available[..take]);
                reader.consume(take);
                // Strip the trailing '\n' (and a preceding '\r') like `lines()`.
                let mut len = buf.len();
                if buf.last() == Some(&b'\n') {
                    len -= 1;
                    if len > 0 && buf[len - 1] == b'\r' {
                        len -= 1;
                    }
                }
                buf.truncate(len);
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
            }
            None => {
                let take = available.len();
                if buf.len() + take > max_bytes {
                    // Oversized: drain through the next newline without
                    // storing a single byte, then fail closed.
                    reader.consume(take);
                    let _ = discard_through_newline(reader)?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line exceeds --max-line-bytes ({} bytes)", max_bytes),
                    ));
                }
                buf.extend_from_slice(available);
                reader.consume(take);
            }
        }
    }
}

/// Consumes bytes up to and including the next newline, buffering nothing.
/// Returns false at EOF without a trailing newline.
fn discard_through_newline<R: BufRead>(reader: &mut R) -> io::Result<bool> {
    loop {
        let available = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(false);
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                reader.consume(idx + 1);
                return Ok(true);
            }
            None => {
                let len = available.len();
                reader.consume(len);
            }
        }
    }
}

/// Processes an inbound JSON-RPC request (Host stdin -> Child stdin),
/// supporting single requests and batch arrays.
pub fn process_inbound_line(
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
) -> InboundAction {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return InboundAction::Forward(line.to_string());
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(val) => process_inbound_value(val, line, vault, acl),
        // Malformed JSON must never bypass exfiltration scanning: fail closed
        // with a JSON-RPC parse error instead of forwarding verbatim.
        Err(_) => InboundAction::BlockParseError,
    }
}

/// Processes an already-parsed inbound JSON value.
fn process_inbound_value(
    mut val: Value,
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
) -> InboundAction {
    match &mut val {
        Value::Object(map) => {
            if let Some(action) = process_single_inbound_request(map, vault, acl) {
                return match action {
                    InboundAction::Drop => InboundAction::Drop,
                    other => other,
                };
            }
        }
        Value::Array(arr) => {
            // Per-element results: a blocked batch element must not discard
            // the other elements. Blocked notifications (no `id`) are dropped
            // entirely.
            let mut any_blocked = false;
            let mut to_child: Vec<Value> = Vec::with_capacity(arr.len());
            let mut to_host: Vec<Value> = Vec::with_capacity(arr.len());
            for elem in arr {
                match elem {
                    Value::Object(map) => match process_single_inbound_request(map, vault, acl) {
                        Some(InboundAction::Drop) => {
                            any_blocked = true;
                        }
                        Some(InboundAction::BlockWithError(err)) => {
                            any_blocked = true;
                            match serde_json::from_str::<Value>(&err) {
                                Ok(err_val) => to_host.push(err_val),
                                Err(_) => to_host.push(elem.take()),
                            }
                        }
                        Some(InboundAction::BlockParseError) => {
                            any_blocked = true;
                            to_host.push(parse_error_response(&Value::Null));
                        }
                        _ => to_child.push(elem.take()),
                    },
                    other => to_child.push(other.take()),
                }
            }
            if any_blocked {
                // Error responses must go to the host (stdout), not the child;
                // allowed elements still reach the child so a mixed batch is
                // split across both channels.
                let to_host = serde_json::to_string(&to_host).unwrap_or_else(|_| "[]".to_string());
                let to_child = if to_child.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&to_child).unwrap_or_else(|_| "[]".to_string()))
                };
                return InboundAction::BatchSplit { to_child, to_host };
            }
        }
        _ => {}
    }

    let out_str = serde_json::to_string(&val).unwrap_or_else(|_| line.to_string());
    InboundAction::Forward(out_str)
}

/// JSON-RPC parse error response (-32700) emitted when an inbound line is not
/// valid JSON — malformed payloads must fail closed.
fn parse_error_response(id: &Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32700,
            "message": "Parse error"
        }
    })
}

/// MCP request methods whose `params` may carry PII / vault tokens and are
/// therefore scanned inbound (exfiltration check + rehydration).
const SCANNED_METHODS: [&str; 4] = [
    "tools/call",
    "resources/read",
    "prompts/get",
    "sampling/createMessage",
];

fn process_single_inbound_request(
    map: &mut serde_json::Map<String, Value>,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
) -> Option<InboundAction> {
    let method = map.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if !SCANNED_METHODS.contains(&method) {
        return None;
    }
    let tool_name = map
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or(method);

    let trust_level = acl.get_trust_level(tool_name);
    let id_val = map.get("id").cloned().unwrap_or(Value::Null);
    let has_id = map.get("id").is_some();

    if let Some(params) = map.get_mut("params") {
        // Structured error response helper keeps the per-field loop below
        // readable while preserving the original JSON-RPC id.
        let blocked = |err: &SecurityError| -> String {
            match err {
                SecurityError::ExfiltrationBlocked { token } => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "error": {
                        "code": -32001,
                        "message": "PII exfiltration blocked for untrusted tool",
                        "data": { "token": token }
                    }
                })
                .to_string(),
                other => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "error": {
                        "code": -32002,
                        "message": other.to_string(),
                    }
                })
                .to_string(),
            }
        };
        // Blocked notifications (no `id`) must not receive a JSON-RPC error
        // response: the request is silently dropped instead.
        let respond_blocked = |err: &SecurityError| -> InboundAction {
            if has_id {
                InboundAction::BlockWithError(blocked(err))
            } else {
                InboundAction::Drop
            }
        };

        // Rehydrate/check every field of `params`, not just `arguments`.
        // `_meta`, sibling fields, and non-object params could otherwise
        // smuggle raw PII or tokens past trust checks. `name` is the tool
        // identifier, so it never carries PII.
        match params {
            Value::Object(obj) => {
                for (key, value) in obj.iter_mut() {
                    // Trusted tools keep their tool identifier untouched;
                    // untrusted calls still scan `name` for exfiltration.
                    if key == "name" && trust_level == ToolTrustLevel::InternalTrusted {
                        continue;
                    }
                    if let Err(err) =
                        vault.rehydrate_json_value_with_key(value, trust_level, Some(key))
                    {
                        return Some(respond_blocked(&err));
                    }
                }
            }
            other => {
                if let Err(err) = vault.rehydrate_json_value(other, trust_level) {
                    return Some(respond_blocked(&err));
                }
            }
        }
    }
    None
}

fn value_is_tools_call(val: &Value) -> bool {
    let is_call = |v: &Value| v.get("method").and_then(|m| m.as_str()) == Some("tools/call");
    match val {
        Value::Object(_) => is_call(val),
        Value::Array(arr) => arr.iter().any(is_call),
        _ => false,
    }
}

/// Returns true when the payload (single or batch element) is a request for
/// any inbound-scanned method (`SCANNED_METHODS`), i.e. one whose `params` are
/// scanned and may carry vault tokens.
fn value_has_scanned_method(val: &Value) -> bool {
    let is_scanned = |v: &Value| {
        v.get("method")
            .and_then(|m| m.as_str())
            .is_some_and(|m| SCANNED_METHODS.contains(&m))
    };
    match val {
        Value::Object(_) => is_scanned(val),
        Value::Array(arr) => arr.iter().any(is_scanned),
        _ => false,
    }
}

/// Returns true when the JSON-RPC payload (single or batch) is a `tools/call`.
pub fn payload_is_tools_call(line: &str) -> bool {
    serde_json::from_str::<Value>(line.trim())
        .map(|val| value_is_tools_call(&val))
        .unwrap_or(false)
}

fn sync_error_value(id: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32003,
            "message": "PII vault store synchronization failed"
        }
    })
}

/// Fail-closed JSON-RPC error returned when the distributed store cannot be
/// synchronized before an inbound tool call. Batch requests get one error per
/// `tools/call` element so the client can correlate responses by id.
///
/// Raw store error strings are logged to stderr only — they must never leak
/// internal topology or credentials into the JSON-RPC channel.
pub fn storage_sync_error_response(line: &str, detail: &str) -> String {
    eprintln!(
        "pii-mcp-proxy error: vault store synchronization failed: {}",
        detail
    );
    let Ok(val) = serde_json::from_str::<Value>(line.trim()) else {
        return sync_error_value(Value::Null).to_string();
    };
    match val {
        Value::Object(map) => {
            sync_error_value(map.get("id").cloned().unwrap_or(Value::Null)).to_string()
        }
        Value::Array(arr) => {
            let errors: Vec<Value> = arr
                .iter()
                .filter(|v| value_has_scanned_method(v))
                .map(|v| sync_error_value(v.get("id").cloned().unwrap_or(Value::Null)))
                .collect();
            if errors.is_empty() {
                sync_error_value(Value::Null).to_string()
            } else {
                Value::Array(errors).to_string()
            }
        }
        _ => sync_error_value(Value::Null).to_string(),
    }
}

/// Persists any dirty tokens accumulated by outbound redaction to the
/// distributed store, clearing them only after the write succeeds.
///
/// Called after every outbound line, on child EOF, and immediately before an
/// inbound `tools/call` so a second pod can always hydrate the latest tokens.
/// Returns `Err` with the store error when the write fails; callers decide
/// whether that is fatal for the current message (fail closed on tool calls,
/// warn otherwise). Pending tokens are retained for the next attempt.
pub fn flush_pending_dirty_entries(
    vault: &Arc<Mutex<PiiSessionVault>>,
    store: Option<&dyn PiiVaultStore<Error = String>>,
    session_id: Option<&str>,
) -> Result<(), String> {
    let (Some(store), Some(sid)) = (store, session_id) else {
        return Ok(());
    };
    let pending = {
        let v = vault
            .lock()
            .map_err(|_| "vault mutex poisoned while sealing dirty entries".to_string())?;
        v.seal_dirty_entries(sid)
    };
    if pending.is_empty() {
        return Ok(());
    }
    let flushed: Vec<String> = pending.iter().map(|(token, _)| token.clone()).collect();
    store.put_entries(sid, pending)?;
    let mut v = vault
        .lock()
        .map_err(|_| "vault mutex poisoned while clearing dirty entries".to_string())?;
    v.clear_dirty_tokens(&flushed);
    Ok(())
}

/// Fetches the remote session snapshot for a `tools/call`, performing network
/// I/O **without** holding the vault mutex. Returns `Ok(None)` for payloads
/// that do not need store access.
pub fn fetch_entries_for_request(
    line: &str,
    store: &dyn PiiVaultStore<Error = String>,
    session_id: &str,
) -> Result<Option<Vec<(String, String)>>, String> {
    match serde_json::from_str::<Value>(line.trim()) {
        Ok(val) => fetch_entries_for_value(&val, store, session_id),
        Err(_) => Ok(None),
    }
}

/// Parsed-value variant of [`fetch_entries_for_request`] so callers can avoid
/// re-parsing the same inbound line.
fn fetch_entries_for_value(
    val: &Value,
    store: &dyn PiiVaultStore<Error = String>,
    session_id: &str,
) -> Result<Option<Vec<(String, String)>>, String> {
    if !value_has_scanned_method(val) {
        return Ok(None);
    }
    store.get_entries(session_id).map(Some)
}

/// Imports a prefetched store snapshot into the vault, then processes the
/// inbound request. Any import failure fails closed with `-32003`.
pub fn process_inbound_line_prefetched(
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
    prefetched: Option<Vec<(String, String)>>,
    session_id: &str,
) -> InboundAction {
    match serde_json::from_str::<Value>(line.trim()) {
        Ok(val) => process_inbound_value_prefetched(val, line, vault, acl, prefetched, session_id),
        Err(_) => process_inbound_line(line, vault, acl),
    }
}

/// Parsed-value variant of [`process_inbound_line_prefetched`].
fn process_inbound_value_prefetched(
    val: Value,
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
    prefetched: Option<Vec<(String, String)>>,
    session_id: &str,
) -> InboundAction {
    if let Some(entries) = prefetched {
        let entry_refs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if let Err(e) = vault.import_sealed_entries(entry_refs, session_id) {
            return InboundAction::BlockWithError(storage_sync_error_response(
                line,
                &e.to_string(),
            ));
        }
    }
    process_inbound_value(val, line, vault, acl)
}

/// Convenience wrapper used by STDIO filter mode (single-threaded). Parses the
/// line once and reuses the value for store detection and request processing.
pub fn process_inbound_line_synced(
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
    store: Option<&dyn PiiVaultStore<Error = String>>,
    session_id: Option<&str>,
) -> InboundAction {
    let Some(val) = serde_json::from_str::<Value>(line.trim()).ok() else {
        return process_inbound_line(line, vault, acl);
    };
    let prefetched = match (store, session_id) {
        (Some(store), Some(sid)) => match fetch_entries_for_value(&val, store, sid) {
            Ok(entries) => entries,
            Err(e) => {
                return InboundAction::BlockWithError(storage_sync_error_response(line, &e));
            }
        },
        _ => None,
    };
    process_inbound_value_prefetched(val, line, vault, acl, prefetched, session_id.unwrap_or(""))
}

/// Processes outbound Child stdout lines, redacting string leaves in result/error/params.
pub fn process_outbound_line(line: &str, vault: &mut PiiSessionVault) -> String {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return line.to_string();
    }

    let Ok(mut val) = serde_json::from_str::<Value>(trimmed) else {
        // Fall back to plain string redaction for non-JSON lines
        return vault.redact(line);
    };

    match &mut val {
        Value::Object(map) => {
            for (k, v) in map {
                // Keep structural fields untouched
                if k == "jsonrpc" || k == "id" || k == "method" {
                    continue;
                }
                vault.redact_json_value_with_key(v, Some(k));
            }
        }
        Value::Array(arr) => {
            // Batch arrays: redact each element but keep structural keys untouched.
            for elem in arr {
                if let Value::Object(map) = elem {
                    for (k, v) in map {
                        if k == "jsonrpc" || k == "id" || k == "method" {
                            continue;
                        }
                        vault.redact_json_value_with_key(v, Some(k));
                    }
                } else {
                    vault.redact_json_value(elem);
                }
            }
        }
        _ => vault.redact_json_value(&mut val),
    }

    serde_json::to_string(&val).unwrap_or_else(|_| line.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTokenFormat {
    Sequential,
    CompactHash,
    StatelessSealed,
}

impl From<ProxyTokenFormat> for TokenFormat {
    fn from(f: ProxyTokenFormat) -> TokenFormat {
        match f {
            ProxyTokenFormat::Sequential => TokenFormat::Sequential,
            ProxyTokenFormat::CompactHash => TokenFormat::CompactHash,
            ProxyTokenFormat::StatelessSealed => TokenFormat::StatelessSealed,
        }
    }
}

#[derive(Debug)]
pub struct ProxyConfig {
    pub trusted_tools: Vec<String>,
    pub trust_all: bool,
    pub locales: Vec<String>,
    pub rules_files: Vec<String>,
    pub token_format: ProxyTokenFormat,
    pub stdio_filter: bool,
    pub session_key: Option<[u8; 32]>,
    pub child_cmd: Option<(String, Vec<String>)>,
    /// Valkey/Redis URL for distributed session persistence.
    pub valkey_url: Option<String>,
    /// Session identifier used as the store hash key suffix.
    pub session_id: Option<String>,
    /// TTL applied to the session hash on every write.
    pub session_ttl: u64,
    /// Maximum bytes per inbound/outbound line (OOM-DoS guard).
    pub max_line_bytes: usize,
    /// Distributed store hash key prefix.
    pub store_key_prefix: String,
    /// Distributed store connect/read/write timeout.
    pub store_timeout: Duration,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProxyAction {
    Run(ProxyConfig),
    Help,
    Version,
}

/// Parses a token-format string ("sequential", "compact-hash", "stateless-sealed").
pub fn parse_token_format(s: &str) -> Result<ProxyTokenFormat, String> {
    match s {
        "sequential" => Ok(ProxyTokenFormat::Sequential),
        "compact-hash" => Ok(ProxyTokenFormat::CompactHash),
        "stateless-sealed" => Ok(ProxyTokenFormat::StatelessSealed),
        other => Err(format!(
            "Invalid token format '{}': expected sequential, compact-hash, or stateless-sealed",
            other
        )),
    }
}

pub const BUILTIN_LOCALES: [&str; 5] = ["global", "id", "us", "eu", "sg"];

/// Strict CLI + environment parser. Returns Err with a descriptive message for
/// any unknown flag, missing flag value, empty segment, or invalid env value.
pub fn parse_cli_and_env(
    args: &[String],
    env_vars: &HashMap<String, String>,
) -> Result<ProxyAction, String> {
    let mut trusted_tools = Vec::new();
    let mut trust_all = false;
    let mut locales = vec!["global".to_string(), "id".to_string()];
    let mut locales_explicit = false;
    let mut rules_files = Vec::new();
    let mut token_format: Option<ProxyTokenFormat> = None;
    let mut stdio_filter = false;
    let mut session_key: Option<[u8; 32]> = None;
    let mut valkey_url: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut session_ttl: Option<u64> = None;
    let mut max_line_bytes: Option<usize> = None;
    let mut store_key_prefix: Option<String> = None;
    let mut store_timeout_ms: Option<u64> = None;
    let mut child_cmd_start: Option<usize> = None;

    /// Flags that consume a value. A value starting with `-` is only treated
    /// as a missing flag value when it matches one of these known flags (or
    /// the `--` separator); otherwise a legit `-`-prefixed value is accepted.
    const KNOWN_VALUE_FLAGS: [&str; 11] = [
        "--trusted-tools",
        "--locales",
        "--rules-file",
        "--token-format",
        "--valkey-url",
        "--redis-url",
        "--session-id",
        "--session-ttl",
        "--max-line-bytes",
        "--store-key-prefix",
        "--store-timeout",
    ];

    fn next_value(args: &[String], i: usize) -> Result<&str, String> {
        match args.get(i + 1).map(|s| s.as_str()) {
            // A value that looks like another known flag (or the child-command
            // separator) means the argument was omitted; never swallow it.
            // Any other `-`-prefixed token is accepted as a real value.
            Some(val)
                if !val.starts_with('-')
                    || !KNOWN_VALUE_FLAGS.contains(&val)
                        && val != "--"
                        && !val.starts_with("--") =>
            {
                Ok(val)
            }
            _ => Err(format!("Missing value for flag '{}'", args[i])),
        }
    }

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--trusted-tools" => {
                let raw = next_value(args, i)?;
                for seg in raw.split(',') {
                    if seg.trim().is_empty() {
                        return Err("Empty tool name in --trusted-tools".to_string());
                    }
                    trusted_tools.push(seg.trim().to_string());
                }
                i += 1;
            }
            "--trust-all-tools" => {
                trust_all = true;
            }
            "--locales" => {
                let raw = next_value(args, i)?;
                let mut parsed_locales = Vec::new();
                for seg in raw.split(',') {
                    let seg = seg.trim();
                    if seg.is_empty() {
                        return Err(format!(
                            "Empty locale segment in --locales '{}' (did you mean 'none'?)",
                            raw
                        ));
                    }
                    parsed_locales.push(seg.to_string());
                }
                // Repeated --locales accumulate; the first occurrence drops
                // the built-in ["global", "id"] default.
                if !locales_explicit {
                    locales.clear();
                    locales_explicit = true;
                }
                locales.extend(parsed_locales);
                i += 1;
            }
            "--rules-file" => {
                let raw = next_value(args, i)?;
                for seg in raw.split(',') {
                    let seg = seg.trim();
                    if seg.is_empty() {
                        return Err(format!(
                            "Empty rules file segment in --rules-file '{}'",
                            raw
                        ));
                    }
                    rules_files.push(seg.to_string());
                }
                i += 1;
            }
            "--stdio-filter" => {
                stdio_filter = true;
            }
            "--token-format" => {
                let raw = next_value(args, i)?;
                token_format = Some(parse_token_format(raw.trim())?);
                i += 1;
            }
            "--valkey-url" | "--redis-url" => {
                let raw = next_value(args, i)?;
                if raw.trim().is_empty() {
                    return Err("--valkey-url must not be empty".to_string());
                }
                valkey_url = Some(raw.trim().to_string());
                i += 1;
            }
            "--session-id" => {
                let raw = next_value(args, i)?;
                if raw.trim().is_empty() {
                    return Err("--session-id must not be empty".to_string());
                }
                session_id = Some(raw.trim().to_string());
                i += 1;
            }
            "--session-ttl" => {
                let raw = next_value(args, i)?;
                let ttl: u64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid --session-ttl '{}': expected seconds", raw))?;
                if ttl == 0 || ttl > i64::MAX as u64 {
                    return Err(format!(
                        "--session-ttl must be between 1 and {} seconds",
                        i64::MAX
                    ));
                }
                session_ttl = Some(ttl);
                i += 1;
            }
            "--max-line-bytes" => {
                let raw = next_value(args, i)?;
                let n: usize = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid --max-line-bytes '{}': expected bytes", raw))?;
                if n == 0 {
                    return Err("--max-line-bytes must be greater than zero".to_string());
                }
                max_line_bytes = Some(n);
                i += 1;
            }
            "--store-key-prefix" => {
                let raw = next_value(args, i)?;
                if raw.trim().is_empty() {
                    return Err("--store-key-prefix must not be empty".to_string());
                }
                store_key_prefix = Some(raw.trim().to_string());
                i += 1;
            }
            "--store-timeout" => {
                let raw = next_value(args, i)?;
                let ms: u64 = raw.trim().parse().map_err(|_| {
                    format!("Invalid --store-timeout '{}': expected milliseconds", raw)
                })?;
                if ms == 0 {
                    return Err("--store-timeout must be greater than zero".to_string());
                }
                store_timeout_ms = Some(ms);
                i += 1;
            }
            "--help" | "-h" => return Ok(ProxyAction::Help),
            "--version" | "-V" => return Ok(ProxyAction::Version),
            "--" => {
                if i + 1 < args.len() {
                    child_cmd_start = Some(i + 1);
                } else {
                    return Err("Missing child command after '--'".to_string());
                }
                break;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown argument: {}", other));
                }
                child_cmd_start = Some(i);
                break;
            }
        }
        i += 1;
    }

    // Env: session key (fail closed on invalid value)
    if let Some(key_hex) = env_vars.get("PII_SHIELD_SESSION_KEY") {
        let key_hex = key_hex.trim();
        if key_hex.is_empty() {
            return Err("PII_SHIELD_SESSION_KEY is set but empty".to_string());
        }
        let bytes =
            hex::decode(key_hex).map_err(|e| format!("Invalid PII_SHIELD_SESSION_KEY: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid PII_SHIELD_SESSION_KEY: expected 32 bytes of hex (64 chars), got {} bytes",
                bytes.len()
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        session_key = Some(k);
    }

    // Env: distributed store configuration (CLI wins over env).
    if valkey_url.is_none() {
        for name in ["PII_SHIELD_VALKEY_URL", "PII_SHIELD_REDIS_URL"] {
            if let Some(url) = env_vars.get(name) {
                let url = url.trim();
                if url.is_empty() {
                    return Err(format!("{} is set but empty", name));
                }
                valkey_url = Some(url.to_string());
                break;
            }
        }
    }
    if session_id.is_none() {
        if let Some(id) = env_vars.get("PII_SHIELD_SESSION_ID") {
            let id = id.trim();
            if id.is_empty() {
                return Err("PII_SHIELD_SESSION_ID is set but empty".to_string());
            }
            session_id = Some(id.to_string());
        }
    }
    if session_ttl.is_none() {
        if let Some(raw) = env_vars.get("PII_SHIELD_SESSION_TTL") {
            let ttl: u64 = raw.trim().parse().map_err(|_| {
                format!("Invalid PII_SHIELD_SESSION_TTL '{}': expected seconds", raw)
            })?;
            if ttl == 0 || ttl > i64::MAX as u64 {
                return Err(format!(
                    "PII_SHIELD_SESSION_TTL must be between 1 and {} seconds",
                    i64::MAX
                ));
            }
            session_ttl = Some(ttl);
        }
    }
    if max_line_bytes.is_none() {
        if let Some(raw) = env_vars.get("PII_SHIELD_MAX_LINE_BYTES") {
            let n: usize = raw.trim().parse().map_err(|_| {
                format!(
                    "Invalid PII_SHIELD_MAX_LINE_BYTES '{}': expected bytes",
                    raw
                )
            })?;
            if n == 0 {
                return Err("PII_SHIELD_MAX_LINE_BYTES must be greater than zero".to_string());
            }
            max_line_bytes = Some(n);
        }
    }
    if store_key_prefix.is_none() {
        if let Some(raw) = env_vars.get("PII_SHIELD_STORE_KEY_PREFIX") {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err("PII_SHIELD_STORE_KEY_PREFIX is set but empty".to_string());
            }
            store_key_prefix = Some(raw.to_string());
        }
    }
    if store_timeout_ms.is_none() {
        if let Some(raw) = env_vars.get("PII_SHIELD_STORE_TIMEOUT") {
            let ms: u64 = raw.trim().parse().map_err(|_| {
                format!(
                    "Invalid PII_SHIELD_STORE_TIMEOUT '{}': expected milliseconds",
                    raw
                )
            })?;
            if ms == 0 {
                return Err("PII_SHIELD_STORE_TIMEOUT must be greater than zero".to_string());
            }
            store_timeout_ms = Some(ms);
        }
    }
    let session_ttl_configured = session_ttl.is_some();
    let session_ttl = session_ttl.unwrap_or(3600);
    let max_line_bytes = max_line_bytes.unwrap_or(DEFAULT_MAX_LINE_BYTES);
    let store_key_prefix =
        store_key_prefix.unwrap_or_else(|| ProxyStore::default_key_prefix().to_string());
    let store_timeout =
        Duration::from_millis(store_timeout_ms.unwrap_or(ProxyStore::default_timeout_millis()));

    // Env / CLI token format resolution
    if token_format.is_none() {
        if let Some(fmt) = env_vars.get("PII_SHIELD_TOKEN_FORMAT") {
            token_format = Some(parse_token_format(fmt.trim())?);
        }
    }
    // PII_SHIELD_STATELESS: validated unconditionally (fail closed on
    // invalid values even when --token-format / PII_SHIELD_TOKEN_FORMAT is
    // also present); applied only when no other token format was set.
    if let Some(stateless) = env_vars.get("PII_SHIELD_STATELESS") {
        match stateless.trim() {
            "1" | "true" => {
                if token_format.is_none() {
                    token_format = Some(ProxyTokenFormat::StatelessSealed);
                }
            }
            "0" | "false" | "" => {}
            other => {
                return Err(format!(
                    "Invalid PII_SHIELD_STATELESS value '{}': expected 1, true, 0, false, or empty",
                    other
                ))
            }
        }
    }

    // Locale / rules-file path split: items ending in .toml or containing a
    // path separator are treated as external rule files.
    let mut builtins = Vec::new();
    let mut none_requested = false;
    for loc in &locales {
        let looks_like_path = loc.ends_with(".toml") || loc.contains('/') || loc.contains('\\');
        if looks_like_path {
            rules_files.push(loc.clone());
        } else if loc == "none" {
            // Explicit opt-out of built-in locales.
            none_requested = true;
        } else {
            if !BUILTIN_LOCALES.contains(&loc.as_str()) {
                return Err(format!(
                    "Unknown locale '{}': expected one of global, id, us, eu, sg, 'none', or a .toml rules file path",
                    loc
                ));
            }
            builtins.push(loc.clone());
        }
    }
    if none_requested && !builtins.is_empty() {
        return Err("'none' must not be combined with other built-in locale names".to_string());
    }
    let locales = if none_requested { Vec::new() } else { builtins };

    // Distributed store fail-closed validation: a misconfigured multi-pod
    // deployment must never start with per-pod tokens or an unreadable store.
    if valkey_url.is_none() && (session_id.is_some() || session_ttl_configured) {
        return Err(
            "--session-id / --session-ttl (or their PII_SHIELD_SESSION_ID / PII_SHIELD_SESSION_TTL aliases) require --valkey-url"
                .to_string(),
        );
    }
    if valkey_url.is_some() {
        if session_id.as_deref().unwrap_or("").is_empty() {
            return Err(
                "--valkey-url requires a non-empty --session-id (or PII_SHIELD_SESSION_ID)"
                    .to_string(),
            );
        }
        if session_key.is_none() {
            return Err(
                "--valkey-url requires PII_SHIELD_SESSION_KEY (32-byte hex) so every pod derives identical tokens"
                    .to_string(),
            );
        }
        if token_format == Some(ProxyTokenFormat::Sequential) {
            return Err(
                "--token-format sequential cannot be used with --valkey-url: per-pod sequential counters cause StateConflict across pods"
                    .to_string(),
            );
        }
        if token_format == Some(ProxyTokenFormat::StatelessSealed) {
            return Err(
                "--token-format stateless-sealed cannot be used with --valkey-url: sealed tokens never write session state to the store"
                    .to_string(),
            );
        }
        if token_format.is_none() {
            // Compact hashes are deterministic across pods; sequential ones are not.
            token_format = Some(ProxyTokenFormat::CompactHash);
        }
    }

    // Fail closed: STDIO filter mode (explicit --stdio-filter, or implicit
    // when no child command is given) performs no outbound redaction, so
    // stateful tokens (sequential / compact-hash) can never be generated
    // there, and stateless-sealed tokens cannot decrypt cross-invocation
    // without a persistent key.
    if stdio_filter && child_cmd_start.is_some() {
        return Err(
            "--stdio-filter cannot be combined with a child command; remove '--' or drop --stdio-filter"
                .to_string(),
        );
    }
    if stdio_filter || child_cmd_start.is_none() {
        let mode_name = if stdio_filter {
            "--stdio-filter"
        } else {
            "STDIO filter mode (no child command)"
        };
        // With a distributed store, filter mode can hydrate compact-hash
        // tokens on inbound tools/call. Without one, only self-contained
        // stateless-sealed tokens can be decrypted in a redaction-less pass.
        let valid_filter_format = if valkey_url.is_some() {
            token_format == Some(ProxyTokenFormat::CompactHash)
        } else {
            token_format == Some(ProxyTokenFormat::StatelessSealed)
        };
        if !valid_filter_format {
            return Err(format!(
                "{} requires --token-format stateless-sealed, or --valkey-url with compact-hash tokens",
                mode_name
            ));
        }
        if session_key.is_none() {
            return Err(format!(
                "{} requires PII_SHIELD_SESSION_KEY for stateless-sealed tokens",
                mode_name
            ));
        }
    }

    let child_cmd = child_cmd_start.map(|idx| (args[idx].clone(), args[idx + 1..].to_vec()));

    Ok(ProxyAction::Run(ProxyConfig {
        trusted_tools,
        trust_all,
        locales,
        rules_files,
        token_format: token_format.unwrap_or(ProxyTokenFormat::Sequential),
        stdio_filter,
        session_key,
        child_cmd,
        valkey_url,
        session_id,
        session_ttl,
        max_line_bytes,
        store_key_prefix,
        store_timeout,
    }))
}

/// Builds a fail-closed vault from the parsed proxy configuration.
pub fn build_vault(config: &ProxyConfig) -> Result<PiiSessionVault, String> {
    let loc_refs: Vec<&str> = config.locales.iter().map(|s| s.as_str()).collect();
    let mut catalog = if loc_refs.is_empty() {
        PiiCatalog::new()
    } else {
        PiiCatalog::with_locales(&loc_refs).map_err(|e| format!("Failed to load locales: {}", e))?
    };

    for path in &config.rules_files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read rules file '{}': {}", path, e))?;
        catalog
            .merge_toml_str(&content)
            .map_err(|e| format!("Invalid rules file '{}': {}", path, e))?;
    }

    if catalog.rules.is_empty() {
        return Err(
            "Fail-closed: merged PII catalog contains 0 rules; refusing to start proxy".to_string(),
        );
    }

    let mut vault = match config.session_key {
        Some(key) => PiiSessionVault::try_from_catalog_with_key(catalog, key),
        None => PiiSessionVault::try_from_catalog(catalog),
    }
    .map_err(|e| format!("Failed to compile PII catalog: {}", e))?;
    vault.set_token_format(config.token_format.into());
    Ok(vault)
}

const HELP_TEXT: &str = "\
pii-mcp-proxy - zero-trust bidirectional MCP STDIO proxy for PII redaction/rehydration

USAGE:
    pii-mcp-proxy [OPTIONS] [-- <CHILD_CMD> <ARGS>...]

OPTIONS:
    --trusted-tools <list>     Comma-separated tools allowed to rehydrate PII
    --trust-all-tools          Allow all tools to rehydrate PII (dangerous)
    --locales <list>           Comma-separated built-in locales (global, id, us, eu, sg),
                               'none', or .toml rules file paths [default: global,id]
    --rules-file <path>        External TOML rules file (repeatable or comma-separated)
    --stdio-filter             Run in pure STDIO filtering mode (no child command);
                               requires stateless-sealed tokens, or compact-hash
                               tokens with --valkey-url, plus PII_SHIELD_SESSION_KEY
    --token-format <fmt>       sequential | compact-hash | stateless-sealed
    --valkey-url <url>         Valkey/Redis URL (alias: --redis-url); enables
                               distributed session persistence across pods
    --session-id <id>          Shared session id used as the store hash key
    --session-ttl <secs>       TTL applied to the session hash [default: 3600]
    --max-line-bytes <bytes>   Maximum inbound/outbound line size [default: 16777216]
    --store-key-prefix <pfx>   Redis/Valkey hash key prefix [default: pii:v1]
    --store-timeout <ms>       Redis/Valkey connect/read/write timeout [default: 500]
    -h, --help                 Show this help
    -V, --version              Show version

ENVIRONMENT:
    PII_SHIELD_SESSION_KEY     64-char hex (32 bytes) shared session key
    PII_SHIELD_TOKEN_FORMAT    Alias for --token-format
    PII_SHIELD_STATELESS=1     Alias for --token-format stateless-sealed
    PII_SHIELD_VALKEY_URL      Alias for --valkey-url (PII_SHIELD_REDIS_URL accepted)
    PII_SHIELD_SESSION_ID      Alias for --session-id
    PII_SHIELD_SESSION_TTL     Alias for --session-ttl
    PII_SHIELD_MAX_LINE_BYTES  Alias for --max-line-bytes
    PII_SHIELD_STORE_KEY_PREFIX Alias for --store-key-prefix
    PII_SHIELD_STORE_TIMEOUT   Alias for --store-timeout

Fail-closed: unknown flags, invalid rules, unknown locales, or an empty catalog
exits with status code 2. Running without a child command enters STDIO filter
mode, which requires PII_SHIELD_SESSION_KEY and either stateless-sealed tokens
or compact-hash tokens with --valkey-url.
";

fn main() {
    let args: Vec<String> = env::args().collect();
    let env_keys = [
        "PII_SHIELD_SESSION_KEY",
        "PII_SHIELD_TOKEN_FORMAT",
        "PII_SHIELD_STATELESS",
        "PII_SHIELD_VALKEY_URL",
        "PII_SHIELD_REDIS_URL",
        "PII_SHIELD_SESSION_ID",
        "PII_SHIELD_SESSION_TTL",
    ];
    let env_vars: HashMap<String, String> = env_keys
        .iter()
        .filter_map(|&k| env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();

    let config = match parse_cli_and_env(&args, &env_vars) {
        Ok(ProxyAction::Help) => {
            print!("{}", HELP_TEXT);
            return;
        }
        Ok(ProxyAction::Version) => {
            println!("pii-mcp-proxy {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Ok(ProxyAction::Run(config)) => config,
        Err(msg) => {
            eprintln!("pii-mcp-proxy error: {}", msg);
            eprintln!("Run with --help for usage.");
            std::process::exit(2);
        }
    };

    let mut vault = match build_vault(&config) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("pii-mcp-proxy error: {}", msg);
            eprintln!("Run with --help for usage.");
            std::process::exit(2);
        }
    };

    // Distributed store: startup hydration is mandatory (fail closed).
    let store: Option<Arc<ProxyStore>> = match config.valkey_url.as_deref() {
        Some(url) => {
            let s = match ProxyStore::redis(
                url,
                config.session_ttl,
                &config.store_key_prefix,
                config.store_timeout,
            ) {
                Ok(s) => s,
                Err(msg) => {
                    eprintln!("pii-mcp-proxy error: {}", msg);
                    std::process::exit(2);
                }
            };
            let session_id = config.session_id.as_deref().expect("validated session id");
            if let Err(e) = vault.load_from_store(&s, session_id) {
                eprintln!(
                    "pii-mcp-proxy error: initial vault store load failed for session '{}': {}",
                    session_id, e
                );
                std::process::exit(2);
            }
            Some(Arc::new(s))
        }
        None => None,
    };
    let session_id: Option<String> = config.session_id.clone();

    let acl = ToolAcl::new(config.trusted_tools.clone(), config.trust_all);

    // Filter mode if no child command specified
    if config.stdio_filter || config.child_cmd.is_none() {
        let stdin = io::stdin();
        let stdout = Arc::new(Mutex::new(io::stdout()));
        let mut reader = stdin.lock();
        let max_line_bytes = config.max_line_bytes;

        loop {
            let payload = match read_line_bounded(&mut reader, max_line_bytes) {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("pii-mcp-proxy error: {}", e);
                    // Fail closed: emit a JSON-RPC error and skip the
                    // oversized line (the remainder was already drained).
                    let mut out = stdout.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", parse_error_response(&Value::Null));
                    let _ = out.flush();
                    continue;
                }
            };
            let action = process_inbound_line_synced(
                &payload,
                &mut vault,
                &acl,
                store
                    .as_deref()
                    .map(|s| s as &dyn PiiVaultStore<Error = String>),
                session_id.as_deref(),
            );
            match action {
                InboundAction::Forward(fw) => {
                    let mut out = stdout.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", fw);
                    let _ = out.flush();
                }
                InboundAction::BlockWithError(err) => {
                    let mut out = stdout.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", err);
                    let _ = out.flush();
                }
                InboundAction::BlockParseError => {
                    let mut out = stdout.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", parse_error_response(&Value::Null));
                    let _ = out.flush();
                }
                InboundAction::Drop => {}
                InboundAction::BatchSplit { to_child, to_host } => {
                    let mut out = stdout.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(fw) = to_child {
                        let _ = writeln!(out, "{}", fw);
                    }
                    let _ = writeln!(out, "{}", to_host);
                    let _ = out.flush();
                }
            }
        }
        return;
    }

    let (prog, prog_args) = config.child_cmd.expect("Child command present");

    let mut child = match Command::new(&prog)
        .args(&prog_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "pii-mcp-proxy error: failed to spawn child MCP server '{}': {}",
                prog, e
            );
            std::process::exit(2);
        }
    };

    let child_stdin = child.stdin.take().expect("Child stdin piped");
    let child_stdout = child.stdout.take().expect("Child stdout piped");

    let vault_arc = Arc::new(Mutex::new(vault));
    let stdout_arc = Arc::new(Mutex::new(io::stdout()));
    let max_line_bytes = config.max_line_bytes;

    // Thread 1: Host stdin -> Child stdin (with exfiltration check).
    // Remote store reads happen *before* taking the vault lock so a slow
    // Valkey/Redis round-trip never serializes outbound redaction.
    let vault_t1 = Arc::clone(&vault_arc);
    let stdout_t1 = Arc::clone(&stdout_arc);
    let store_t1 = store.clone();
    let session_id_t1 = session_id.clone();

    let (t1_done_tx, t1_done_rx) = mpsc::channel::<()>();

    let t1 = thread::spawn(move || {
        let stdin = io::stdin();
        let mut child_writer = io::BufWriter::new(child_stdin);
        let mut host_reader = stdin.lock();

        loop {
            let payload = match read_line_bounded(&mut host_reader, max_line_bytes) {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    // Oversized inbound line: fail closed with a JSON-RPC
                    // error instead of buffering it (OOM-DoS guard).
                    eprintln!("pii-mcp-proxy error: {}", e);
                    let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", parse_error_response(&Value::Null));
                    let _ = out.flush();
                    continue;
                }
            };

            // Parse the inbound line once and reuse it for store detection,
            // fail-closed responses, and request processing.
            let parsed = serde_json::from_str::<Value>(payload.trim()).ok();
            let is_tools_call = parsed.as_ref().is_some_and(value_is_tools_call);

            // Flush outbound-created tokens before any inbound tool call so a
            // pod handling the next turn can hydrate them from the store.
            // Pending tokens are retained on failure and retried next time.
            if let Err(e) = flush_pending_dirty_entries(
                &vault_t1,
                store_t1
                    .as_deref()
                    .map(|s| s as &dyn PiiVaultStore<Error = String>),
                session_id_t1.as_deref(),
            ) {
                if is_tools_call {
                    let err_resp = storage_sync_error_response(&payload, &e);
                    let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", err_resp);
                    let _ = out.flush();
                    continue;
                }
                eprintln!(
                    "pii-mcp-proxy warning: vault store flush before inbound request failed: {}",
                    e
                );
            }

            let prefetched = match (store_t1.as_deref(), session_id_t1.as_deref(), &parsed) {
                (Some(store), Some(sid), Some(val)) => {
                    match fetch_entries_for_value(val, store, sid) {
                        Ok(entries) => entries,
                        Err(e) => {
                            let err_resp = storage_sync_error_response(&payload, &e);
                            let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = writeln!(out, "{}", err_resp);
                            let _ = out.flush();
                            continue;
                        }
                    }
                }
                _ => None,
            };

            let action = match parsed {
                Some(val) => {
                    let mut v = vault_t1.lock().unwrap_or_else(|e| e.into_inner());
                    process_inbound_value_prefetched(
                        val,
                        &payload,
                        &mut v,
                        &acl,
                        prefetched,
                        session_id_t1.as_deref().unwrap_or(""),
                    )
                }
                // Malformed JSON must never bypass exfiltration scanning.
                None => InboundAction::BlockParseError,
            };

            match action {
                InboundAction::Forward(fw) => {
                    if writeln!(child_writer, "{}", fw).is_err() || child_writer.flush().is_err() {
                        break;
                    }
                }
                InboundAction::BlockWithError(err_resp) => {
                    let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", err_resp);
                    let _ = out.flush();
                }
                InboundAction::BlockParseError => {
                    let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", parse_error_response(&Value::Null));
                    let _ = out.flush();
                }
                InboundAction::Drop => {}
                InboundAction::BatchSplit { to_child, to_host } => {
                    if let Some(fw) = to_child {
                        if writeln!(child_writer, "{}", fw).is_err()
                            || child_writer.flush().is_err()
                        {
                            break;
                        }
                    }
                    let mut out = stdout_t1.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = writeln!(out, "{}", to_host);
                    let _ = out.flush();
                }
            }
        }
        // child_writer drops here, signaling EOF to child MCP server
        let _ = t1_done_tx.send(());
    });

    // Thread 2: Child stdout -> Host stdout (with redaction + store flush).
    // The dirty-token snapshot is taken under the vault lock, but the network
    // write happens with the lock released; tokens are only cleared after the
    // store confirms success so transient failures are retried next turn.
    let vault_t2 = Arc::clone(&vault_arc);
    let stdout_t2 = Arc::clone(&stdout_arc);
    let store_t2 = store;
    let session_id_t2 = session_id;
    let max_line_bytes_t2 = max_line_bytes;

    let t2 = thread::spawn(move || {
        let mut reader = BufReader::new(child_stdout);
        loop {
            let payload = match read_line_bounded(&mut reader, max_line_bytes_t2) {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    // Oversized child output: drop the line (fail closed,
                    // never buffer it) and keep draining the stream.
                    eprintln!("pii-mcp-proxy error: {}", e);
                    continue;
                }
            };

            let redacted = {
                let mut v = vault_t2.lock().unwrap_or_else(|e| e.into_inner());
                process_outbound_line(&payload, &mut v)
            };

            // Flush after every outbound line so tokens are durable even if no
            // further child output arrives before the next inbound tool call.
            if let Err(e) = flush_pending_dirty_entries(
                &vault_t2,
                store_t2
                    .as_deref()
                    .map(|s| s as &dyn PiiVaultStore<Error = String>),
                session_id_t2.as_deref(),
            ) {
                eprintln!(
                    "pii-mcp-proxy warning: vault store flush failed, pending tokens kept for retry: {}",
                    e
                );
            }

            let mut out = stdout_t2.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(out, "{}", redacted);
            let _ = out.flush();
        }

        // Child EOF: one final flush so the last redacted response's tokens are
        // not lost when no subsequent line can trigger a retry.
        if let Err(e) = flush_pending_dirty_entries(
            &vault_t2,
            store_t2
                .as_deref()
                .map(|s| s as &dyn PiiVaultStore<Error = String>),
            session_id_t2.as_deref(),
        ) {
            eprintln!(
                "pii-mcp-proxy warning: final vault store flush on child EOF failed: {}",
                e
            );
        }
    });

    // Reap the child, then join the I/O threads before exiting so neither is
    // killed mid-write by `std::process::exit`. t2 stops on child EOF; t1's
    // writes then fail on the closed child stdin pipe and it exits too.
    let _ = t2.join();
    let child_status = child.wait();
    // t1 blocks on host stdin, so it may never observe the child's death if
    // the host keeps its stdin open. Joining unconditionally would hang the
    // proxy forever — wait on the completion signal with a grace period, then
    // force exit (the child is already reaped and t2 already flushed).
    let child_exit = match &child_status {
        Ok(status) if !status.success() => Some(status.code().unwrap_or(1)),
        _ => None,
    };
    if t1_done_rx.recv_timeout(Duration::from_millis(500)).is_err() {
        eprintln!(
            "pii-mcp-proxy warning: inbound thread still blocked on host stdin after child exit; forcing shutdown"
        );
        match child_exit {
            Some(code) => std::process::exit(code),
            None => std::process::exit(0),
        }
    }
    let _ = t1.join();
    match child_status {
        Ok(status) if !status.success() => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(_) => {}
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_line_bounded_oversized_line_fails_without_oom() {
        // 64 KiB cap: a 1 MiB line must error without buffering 1 MiB.
        let mut data: Vec<u8> = Vec::new();
        data.extend(std::iter::repeat_n(b'a', 1024 * 1024));
        data.push(b'\n');
        data.extend_from_slice(b"tiny\n");
        let mut reader = io::BufReader::new(&data[..]);
        let err = read_line_bounded(&mut reader, 64 * 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Stream stays in sync: the next line reads cleanly after the drain.
        assert_eq!(
            read_line_bounded(&mut reader, 64 * 1024).unwrap(),
            Some("tiny".to_string())
        );
        assert!(read_line_bounded(&mut reader, 64 * 1024).unwrap().is_none());
    }

    #[test]
    fn test_read_line_bounded_split_lines() {
        let mut data: Vec<u8> = Vec::new();
        data.extend(b"partial");
        let mut reader = io::BufReader::new(&data[..]);
        assert_eq!(
            read_line_bounded(&mut reader, 1024).unwrap(),
            Some("partial".to_string())
        );
        assert!(read_line_bounded(&mut reader, 1024).unwrap().is_none());
    }

    #[test]
    fn test_malformed_json_inbound_fails_closed_32700() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let acl = ToolAcl::new(Vec::new(), false);
        match process_inbound_line("not-json{", &mut vault, &acl) {
            InboundAction::BlockParseError => {}
            other => panic!("malformed JSON must fail closed, got {:?}", other),
        }
    }

    #[test]
    fn test_resources_read_exfiltration_blocked() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");
        let acl = ToolAcl::new(Vec::new(), false);

        let req = r#"{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"file:///x?nik=<ID_NIK_1>"}}"#;
        match process_inbound_line(req, &mut vault, &acl) {
            InboundAction::BlockWithError(err) => assert!(err.contains("-32001"), "{}", err),
            other => panic!("resources/read exfiltration must be blocked: {:?}", other),
        }

        // prompts/get and sampling/createMessage are covered too.
        for method in ["prompts/get", "sampling/createMessage"] {
            let req = format!(
                r#"{{"jsonrpc":"2.0","id":12,"method":"{}","params":{{"q":"<ID_NIK_1>"}}}}"#,
                method
            );
            assert!(
                matches!(
                    process_inbound_line(&req, &mut vault, &acl),
                    InboundAction::BlockWithError(_)
                ),
                "{} exfiltration must be blocked",
                method
            );
        }
    }

    #[test]
    fn test_blocked_notification_is_dropped_not_responded() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");
        let acl = ToolAcl::new(Vec::new(), false);

        // Notification: no `id` at all.
        let req = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}}"#;
        match process_inbound_line(req, &mut vault, &acl) {
            InboundAction::Drop => {}
            other => panic!("blocked notification must be dropped, got {:?}", other),
        }
    }

    #[test]
    fn test_mixed_batch_partial_block_returns_array() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");
        let acl = ToolAcl::new(vec!["query_db".to_string()], false);

        let batch = r#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_db","arguments":{"nik":"<ID_NIK_1>"}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}}
        ]"#;
        let action = process_inbound_line(batch, &mut vault, &acl);
        let InboundAction::BatchSplit { to_child, to_host } = action else {
            panic!("mixed batch must split per-element results");
        };
        // The blocked element's error goes to the host…
        let host_val: Value = serde_json::from_str(&to_host).expect("valid JSON array");
        let host_arr = host_val.as_array().expect("array response");
        assert_eq!(host_arr.len(), 1);
        assert_eq!(host_arr[0]["error"]["code"], -32001);
        // …and the allowed element is still forwarded to the child.
        let child_out = to_child.expect("allowed element forwarded to child");
        let child_val: Value = serde_json::from_str(&child_out).expect("valid JSON array");
        let child_arr = child_val.as_array().expect("array response");
        assert_eq!(child_arr.len(), 1);
        assert!(child_arr[0].get("result").is_some() || child_arr[0].get("method").is_some());
    }

    #[test]
    fn test_batch_blocked_notification_element_is_dropped() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");
        let acl = ToolAcl::new(Vec::new(), false);

        let batch = r#"[
            {"jsonrpc":"2.0","method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}},
            {"jsonrpc":"2.0","id":5,"method":"ping"}
        ]"#;
        let InboundAction::BatchSplit { to_child, to_host } =
            process_inbound_line(batch, &mut vault, &acl)
        else {
            panic!("batch with blocked notification must still return remaining elements");
        };
        // The ping is not blocked, so it is forwarded to the child; the host
        // gets no error responses because the only blocked element was a
        // notification (no `id`).
        let child_out = to_child.expect("ping forwarded to child");
        let child_val: Value = serde_json::from_str(&child_out).expect("valid JSON array");
        assert_eq!(child_val.as_array().expect("array").len(), 1);
        let val: Value = serde_json::from_str(&to_host).expect("valid JSON array");
        let arr = val.as_array().expect("array response");
        assert!(
            arr.is_empty(),
            "blocked notification produces no host response"
        );
    }

    #[test]
    fn test_next_value_accepts_dash_prefixed_non_flag_values() {
        let env = test_env(&[(
            "PII_SHIELD_SESSION_KEY",
            "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb",
        )]);
        let args: Vec<String> = [
            "pii-mcp-proxy",
            "--rules-file",
            "-weird-name.toml",
            "--token-format",
            "stateless-sealed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Should parse the value rather than erroring on the leading '-'.
        let result = parse_cli_and_env(&args, &env);
        match result {
            Ok(ProxyAction::Run(cfg)) => {
                assert!(cfg.rules_files.contains(&"-weird-name.toml".to_string()));
            }
            Ok(_) => panic!("expected Run"),
            Err(e) => panic!("dash-prefixed value must be accepted: {}", e),
        }
    }

    #[test]
    fn test_max_line_bytes_config() {
        let env = test_env(&[(
            "PII_SHIELD_SESSION_KEY",
            "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb",
        )]);
        let args: Vec<String> = [
            "pii-mcp-proxy",
            "--max-line-bytes",
            "1024",
            "--stdio-filter",
            "--token-format",
            "stateless-sealed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let action = parse_cli_and_env(&args, &env).expect("valid config");
        match action {
            ProxyAction::Run(cfg) => assert_eq!(cfg.max_line_bytes, 1024),
            _ => panic!("expected Run"),
        }

        // Env alias.
        let mut env = test_env(&[(
            "PII_SHIELD_SESSION_KEY",
            "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb",
        )]);
        env.insert("PII_SHIELD_MAX_LINE_BYTES".to_string(), "4096".to_string());
        let args: Vec<String> = [
            "pii-mcp-proxy",
            "--stdio-filter",
            "--token-format",
            "stateless-sealed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        match parse_cli_and_env(&args, &env).expect("valid config") {
            ProxyAction::Run(cfg) => assert_eq!(cfg.max_line_bytes, 4096),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_storage_sync_error_response_omits_raw_detail() {
        let single = storage_sync_error_response(
            r#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"a"}}"#,
            "connection refused to redis://internal:6379",
        );
        let val: Value = serde_json::from_str(&single).expect("valid JSON");
        assert!(val["error"].get("data").is_none(), "no raw detail leakage");
        assert_eq!(val["id"], Value::from("req-1"));
    }

    #[test]
    fn test_process_inbound_trusted_vs_untrusted() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");

        let acl = ToolAcl::new(vec!["query_db".to_string()], false);

        // Trusted tool call succeeds
        let trusted_req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_db","arguments":{"nik":"<ID_NIK_1>"}}}"#;
        match process_inbound_line(trusted_req, &mut vault, &acl) {
            InboundAction::Forward(fw) => {
                assert!(fw.contains("3573012203950001"));
            }
            InboundAction::BlockWithError(_) => panic!("Trusted tool must not be blocked"),
            _ => panic!("unexpected action"),
        }

        // Untrusted tool call blocked with JSON-RPC -32001 error
        let untrusted_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}}"#;
        match process_inbound_line(untrusted_req, &mut vault, &acl) {
            InboundAction::BlockWithError(err) => {
                assert!(err.contains("-32001"));
                assert!(err.contains("PII exfiltration blocked"));
            }
            InboundAction::Forward(_) => panic!("Untrusted tool call must be blocked"),
            _ => {}
        }
    }

    #[test]
    fn test_untrusted_params_name_is_scanned_for_exfiltration() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("User 3573012203950001");
        let acl = ToolAcl::new(Vec::new(), false);

        let req =
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"<ID_NIK_1>"}}"#;
        match process_inbound_line(req, &mut vault, &acl) {
            InboundAction::BlockWithError(err) => {
                assert!(err.contains("-32001"), "{}", err);
            }
            InboundAction::Forward(fw) => {
                panic!("token hidden in params.name must be blocked: {}", fw)
            }
            _ => {}
        }
    }

    #[test]
    fn test_storage_sync_error_response_is_batch_aware() {
        let batch = r#"[
            {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"a"}},
            {"jsonrpc":"2.0","id":8,"method":"notifications/progress"},
            {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"b"}},
            {"jsonrpc":"2.0","id":10,"method":"resources/read","params":{"uri":"file:///x"}},
            {"jsonrpc":"2.0","id":11,"method":"prompts/get","params":{"name":"p"}},
            {"jsonrpc":"2.0","id":12,"method":"sampling/createMessage","params":{}},
            {"jsonrpc":"2.0","id":13,"method":"ping"}
        ]"#;
        let response = storage_sync_error_response(batch, "offline");
        let val: Value = serde_json::from_str(&response).expect("valid JSON");
        let arr = val.as_array().expect("batch response array");
        assert_eq!(
            arr.len(),
            5,
            "one error per scanned-method element, none for notifications/ping"
        );
        let ids: Vec<&Value> = arr.iter().map(|v| &v["id"]).collect();
        assert_eq!(
            ids,
            vec![
                &Value::from(7),
                &Value::from(9),
                &Value::from(10),
                &Value::from(11),
                &Value::from(12)
            ]
        );
        assert!(arr.iter().all(|v| v["error"]["code"] == -32003));

        let single = storage_sync_error_response(
            r#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"a"}}"#,
            "offline",
        );
        let val: Value = serde_json::from_str(&single).expect("valid JSON");
        assert_eq!(val["id"], Value::from("req-1"));
    }

    fn test_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn args(items: &[&str]) -> Vec<String> {
        std::iter::once("pii-mcp-proxy".to_string())
            .chain(items.iter().map(|s| s.to_string()))
            .collect()
    }

    const TEST_KEY: &str = "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb";

    #[test]
    fn test_valkey_config_validation_is_fail_closed() {
        // Missing session id.
        let err = parse_cli_and_env(
            &args(&["--valkey-url", "redis://127.0.0.1:6379", "--", "/bin/true"]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("session-id"), "{}", err);

        // Missing shared session key.
        let err = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--",
                "/bin/true",
            ]),
            &test_env(&[]),
        )
        .unwrap_err();
        assert!(err.contains("PII_SHIELD_SESSION_KEY"), "{}", err);

        // Sequential tokens conflict across pods.
        let err = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--token-format",
                "sequential",
                "--",
                "/bin/true",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("sequential"), "{}", err);

        // Zero TTL rejected.
        let err = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--session-ttl",
                "0",
                "--",
                "/bin/true",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("session-ttl"), "{}", err);

        // TTL larger than i64::MAX rejected (would become a negative EXPIRE).
        let err = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--session-ttl",
                "9223372036854775808",
                "--",
                "/bin/true",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("session-ttl"), "{}", err);

        // Orphan --session-id without a store is a misconfiguration.
        let err = parse_cli_and_env(
            &args(&["--session-id", "sess-1", "--", "/bin/true"]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("--valkey-url"), "{}", err);

        // Orphan --session-ttl without a store is a misconfiguration.
        let err = parse_cli_and_env(
            &args(&["--session-ttl", "60", "--", "/bin/true"]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("--valkey-url"), "{}", err);

        // Stateless-sealed tokens never persist, so a store is unusable.
        let err = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--token-format",
                "stateless-sealed",
                "--",
                "/bin/true",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .unwrap_err();
        assert!(err.contains("stateless-sealed"), "{}", err);

        // An empty env URL reports the exact alias that was set.
        let err = parse_cli_and_env(
            &args(&["--", "/bin/true"]),
            &test_env(&[
                ("PII_SHIELD_SESSION_KEY", TEST_KEY),
                ("PII_SHIELD_REDIS_URL", "   "),
            ]),
        )
        .unwrap_err();
        assert!(err.contains("PII_SHIELD_REDIS_URL"), "{}", err);

        // Filter mode accepts compact-hash when a store can hydrate it.
        let action = parse_cli_and_env(
            &args(&[
                "--stdio-filter",
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .expect("filter mode with a store");
        match action {
            ProxyAction::Run(config) => {
                assert!(config.stdio_filter);
                assert_eq!(config.token_format, ProxyTokenFormat::CompactHash);
            }
            _ => panic!("expected Run"),
        }

        let action = parse_cli_and_env(
            &args(&[
                "--valkey-url",
                "redis://127.0.0.1:6379",
                "--session-id",
                "sess-1",
                "--",
                "/bin/true",
            ]),
            &test_env(&[("PII_SHIELD_SESSION_KEY", TEST_KEY)]),
        )
        .expect("valid valkey config");
        match action {
            ProxyAction::Run(config) => {
                assert_eq!(
                    config.token_format,
                    ProxyTokenFormat::CompactHash,
                    "distributed mode must default to compact-hash"
                );
                assert_eq!(config.session_ttl, 3600);
                assert_eq!(config.session_id.as_deref(), Some("sess-1"));
            }
            _ => panic!("expected Run"),
        }

        // Env aliases are accepted (--redis-url is a CLI alias too).
        let action = parse_cli_and_env(
            &args(&["--redis-url", "redis://127.0.0.1:6379", "--", "/bin/true"]),
            &test_env(&[
                ("PII_SHIELD_SESSION_KEY", TEST_KEY),
                ("PII_SHIELD_SESSION_ID", "env-session"),
                ("PII_SHIELD_SESSION_TTL", "120"),
            ]),
        )
        .expect("env valkey config");
        match action {
            ProxyAction::Run(config) => {
                assert_eq!(config.session_id.as_deref(), Some("env-session"));
                assert_eq!(config.session_ttl, 120);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn test_store_hydration_bridges_pods() {
        use pii_core::SecurityPolicy;

        let key = [42u8; 32];
        let session = "session:multi-pod";
        let shared = ProxyStore::memory();

        // Pod A redacts a NIK and persists the sealed entry.
        let mut pod_a = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        pod_a.set_token_format(TokenFormat::CompactHash);
        let masked = pod_a.redact("Customer NIK 3573012203950001");
        let token = masked
            .split_whitespace()
            .find(|w| w.starts_with('<'))
            .expect("token")
            .to_string();
        assert_eq!(pod_a.flush_to_store(&shared, session).unwrap(), 1);

        // Pod B has an empty vault. Trusted tools rehydrate after a store sync.
        let mut pod_b = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        pod_b.set_token_format(TokenFormat::CompactHash);
        let acl = ToolAcl::new(vec!["query_customer".to_string()], false);
        let trusted = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"{}"}}}}}}"#,
            token
        );
        match process_inbound_line_synced(&trusted, &mut pod_b, &acl, Some(&shared), Some(session))
        {
            InboundAction::Forward(fw) => {
                assert!(fw.contains("3573012203950001"), "got {}", fw);
            }
            InboundAction::BlockWithError(e) => panic!("trusted tool blocked: {}", e),
            _ => {}
        }

        // An untrusted tool on Pod B must still be blocked after hydration.
        let untrusted = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"web_search","arguments":{{"q":"{}"}}}}}}"#,
            token
        );
        match process_inbound_line_synced(
            &untrusted,
            &mut pod_b,
            &acl,
            Some(&shared),
            Some(session),
        ) {
            InboundAction::BlockWithError(e) => assert!(e.contains("-32001"), "got {}", e),
            InboundAction::Forward(_) => panic!("untrusted tool must be blocked"),
            _ => {}
        }
    }

    #[test]
    fn test_store_failure_fails_closed_with_32003() {
        use pii_core::SecurityPolicy;

        #[derive(Debug)]
        struct DeadStore;
        impl PiiVaultStore for DeadStore {
            type Error = String;
            fn get_entries(&self, _: &str) -> Result<Vec<(String, String)>, Self::Error> {
                Err("connection refused".to_string())
            }
            fn put_entries(&self, _: &str, _: Vec<(String, String)>) -> Result<(), Self::Error> {
                Err("connection refused".to_string())
            }
        }

        let mut vault = PiiSessionVault::with_key(SecurityPolicy::StandardGlobal, [3u8; 32]);
        let acl = ToolAcl::new(vec![], false);
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"x"}}}"#;
        match process_inbound_line_synced(req, &mut vault, &acl, Some(&DeadStore), Some("s")) {
            InboundAction::BlockWithError(e) => {
                assert!(e.contains("-32003"), "got {}", e);
                assert!(e.contains("PII vault store synchronization failed"));
                assert!(e.contains(r#""id":7"#));
            }
            InboundAction::Forward(_) => panic!("store failure must fail closed"),
            _ => {}
        }

        // Non-tools/call payloads never touch the store.
        let init = r#"{"jsonrpc":"2.0","id":8,"method":"init_data"}"#;
        assert!(matches!(
            process_inbound_line_synced(init, &mut vault, &acl, Some(&DeadStore), Some("s")),
            InboundAction::Forward(_)
        ));
    }

    #[test]
    fn test_process_outbound_preserves_numeric_id() {
        let mut vault = PiiSessionVault::new(pii_core::SecurityPolicy::IndonesiaUuPdpStrict);
        let resp = r#"{"jsonrpc":"2.0","id":3573012203950001,"result":{"content":[{"type":"text","text":"NIK: 3573012203950001"}]}}"#;
        let out = process_outbound_line(resp, &mut vault);
        assert!(out.contains(r#""id":3573012203950001"#));
        assert!(out.contains("<ID_NIK_1>"));
    }
}
