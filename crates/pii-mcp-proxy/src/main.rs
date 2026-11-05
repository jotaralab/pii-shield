use pii_core::{
    PiiCatalog, PiiSessionVault, PiiVaultStore, SecurityError, TokenFormat, ToolTrustLevel,
};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

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

pub enum InboundAction {
    Forward(String),
    BlockWithError(String),
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

    let Ok(mut val) = serde_json::from_str::<Value>(trimmed) else {
        // If not valid JSON, forward as-is
        return InboundAction::Forward(line.to_string());
    };

    match &mut val {
        Value::Object(map) => {
            if let Some(action) = process_single_inbound_request(map, vault, acl) {
                return action;
            }
        }
        Value::Array(arr) => {
            for elem in arr {
                if let Value::Object(map) = elem {
                    if let Some(InboundAction::BlockWithError(err)) =
                        process_single_inbound_request(map, vault, acl)
                    {
                        return InboundAction::BlockWithError(err);
                    }
                }
            }
        }
        _ => {}
    }

    let out_str = serde_json::to_string(&val).unwrap_or_else(|_| line.to_string());
    InboundAction::Forward(out_str)
}

fn process_single_inbound_request(
    map: &mut serde_json::Map<String, Value>,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
) -> Option<InboundAction> {
    if map.get("method").and_then(|v| v.as_str()) == Some("tools/call") {
        let tool_name = map
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");

        let trust_level = acl.get_trust_level(tool_name);
        let id_val = map.get("id").cloned().unwrap_or(Value::Null);

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

            // Rehydrate/check every field of `params`, not just `arguments`.
            // `_meta`, sibling fields, and non-object params could otherwise
            // smuggle raw PII or tokens past trust checks. `name` is the tool
            // identifier, so it never carries PII.
            match params {
                Value::Object(obj) => {
                    for (key, value) in obj.iter_mut() {
                        if key == "name" {
                            continue;
                        }
                        if let Err(err) =
                            vault.rehydrate_json_value_with_key(value, trust_level, Some(key))
                        {
                            return Some(InboundAction::BlockWithError(blocked(&err)));
                        }
                    }
                }
                other => {
                    if let Err(err) = vault.rehydrate_json_value(other, trust_level) {
                        return Some(InboundAction::BlockWithError(blocked(&err)));
                    }
                }
            }
        }
    }
    None
}

/// Returns true when the JSON-RPC payload (single or batch) is a `tools/call`.
pub fn payload_is_tools_call(line: &str) -> bool {
    let Ok(val) = serde_json::from_str::<Value>(line.trim()) else {
        return false;
    };
    let is_call = |v: &Value| v.get("method").and_then(|m| m.as_str()) == Some("tools/call");
    match &val {
        Value::Object(_) => is_call(&val),
        Value::Array(arr) => arr.iter().any(is_call),
        _ => false,
    }
}

fn payload_request_id(line: &str) -> Value {
    let Ok(val) = serde_json::from_str::<Value>(line.trim()) else {
        return Value::Null;
    };
    match &val {
        Value::Object(map) => map.get("id").cloned().unwrap_or(Value::Null),
        Value::Array(arr) => arr
            .iter()
            .find(|v| v.get("method").and_then(|m| m.as_str()) == Some("tools/call"))
            .and_then(|v| v.get("id"))
            .cloned()
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Fail-closed JSON-RPC error returned when the distributed store cannot be
/// synchronized before an inbound tool call.
pub fn storage_sync_error_response(line: &str, detail: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": payload_request_id(line),
        "error": {
            "code": -32003,
            "message": "PII vault store synchronization failed",
            "data": { "detail": detail }
        }
    })
    .to_string()
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
    if !payload_is_tools_call(line) {
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
    process_inbound_line(line, vault, acl)
}

/// Convenience wrapper used by STDIO filter mode (single-threaded).
pub fn process_inbound_line_synced(
    line: &str,
    vault: &mut PiiSessionVault,
    acl: &ToolAcl,
    store: Option<&dyn PiiVaultStore<Error = String>>,
    session_id: Option<&str>,
) -> InboundAction {
    let prefetched = match (store, session_id) {
        (Some(store), Some(sid)) => match fetch_entries_for_request(line, store, sid) {
            Ok(entries) => entries,
            Err(e) => {
                return InboundAction::BlockWithError(storage_sync_error_response(line, &e));
            }
        },
        _ => None,
    };
    process_inbound_line_prefetched(line, vault, acl, prefetched, session_id.unwrap_or(""))
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
    let mut child_cmd_start: Option<usize> = None;

    fn next_value(args: &[String], i: usize) -> Result<&str, String> {
        match args.get(i + 1).map(|s| s.as_str()) {
            // A value that looks like another flag means the argument was
            // omitted; never swallow it.
            Some(val) if !val.starts_with('-') => Ok(val),
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
    let session_ttl_configured = session_ttl.is_some();
    let session_ttl = session_ttl.unwrap_or(3600);

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
                               requires stateless-sealed tokens + PII_SHIELD_SESSION_KEY
    --token-format <fmt>       sequential | compact-hash | stateless-sealed
    --valkey-url <url>         Valkey/Redis URL (alias: --redis-url); enables
                               distributed session persistence across pods
    --session-id <id>          Shared session id used as the store hash key
    --session-ttl <secs>       TTL applied to the session hash [default: 3600]
    -h, --help                 Show this help
    -V, --version              Show version

ENVIRONMENT:
    PII_SHIELD_SESSION_KEY     64-char hex (32 bytes) shared session key
    PII_SHIELD_TOKEN_FORMAT    Alias for --token-format
    PII_SHIELD_STATELESS=1     Alias for --token-format stateless-sealed
    PII_SHIELD_VALKEY_URL      Alias for --valkey-url (PII_SHIELD_REDIS_URL accepted)
    PII_SHIELD_SESSION_ID      Alias for --session-id
    PII_SHIELD_SESSION_TTL     Alias for --session-ttl

Fail-closed: unknown flags, invalid rules, unknown locales, or an empty catalog
exits with status code 2. Running without a child command enters STDIO filter
mode, which requires --token-format stateless-sealed and PII_SHIELD_SESSION_KEY.
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
            let s = match ProxyStore::redis(url, config.session_ttl) {
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

        for line in stdin.lock().lines() {
            let Ok(payload) = line else { break };
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
                    let mut out = stdout.lock().unwrap();
                    let _ = writeln!(out, "{}", fw);
                    let _ = out.flush();
                }
                InboundAction::BlockWithError(err) => {
                    let mut out = stdout.lock().unwrap();
                    let _ = writeln!(out, "{}", err);
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

    // Thread 1: Host stdin -> Child stdin (with exfiltration check).
    // Remote store reads happen *before* taking the vault lock so a slow
    // Valkey/Redis round-trip never serializes outbound redaction.
    let vault_t1 = Arc::clone(&vault_arc);
    let stdout_t1 = Arc::clone(&stdout_arc);
    let store_t1 = store.clone();
    let session_id_t1 = session_id.clone();

    let t1 = thread::spawn(move || {
        let stdin = io::stdin();
        let mut child_writer = io::BufWriter::new(child_stdin);

        for line in stdin.lock().lines() {
            let Ok(payload) = line else { break };

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
                if payload_is_tools_call(&payload) {
                    let err_resp = storage_sync_error_response(&payload, &e);
                    let mut out = stdout_t1.lock().unwrap();
                    let _ = writeln!(out, "{}", err_resp);
                    let _ = out.flush();
                    continue;
                }
                eprintln!(
                    "pii-mcp-proxy warning: vault store flush before inbound request failed: {}",
                    e
                );
            }

            let prefetched = match (store_t1.as_deref(), session_id_t1.as_deref()) {
                (Some(store), Some(sid)) => match fetch_entries_for_request(&payload, store, sid) {
                    Ok(entries) => entries,
                    Err(e) => {
                        let err_resp = storage_sync_error_response(&payload, &e);
                        let mut out = stdout_t1.lock().unwrap();
                        let _ = writeln!(out, "{}", err_resp);
                        let _ = out.flush();
                        continue;
                    }
                },
                _ => None,
            };

            let action = {
                let mut v = vault_t1.lock().unwrap();
                process_inbound_line_prefetched(
                    &payload,
                    &mut v,
                    &acl,
                    prefetched,
                    session_id_t1.as_deref().unwrap_or(""),
                )
            };

            match action {
                InboundAction::Forward(fw) => {
                    if writeln!(child_writer, "{}", fw).is_err() || child_writer.flush().is_err() {
                        break;
                    }
                }
                InboundAction::BlockWithError(err_resp) => {
                    let mut out = stdout_t1.lock().unwrap();
                    let _ = writeln!(out, "{}", err_resp);
                    let _ = out.flush();
                }
            }
        }
        // child_writer drops here, signaling EOF to child MCP server
    });

    // Thread 2: Child stdout -> Host stdout (with redaction + store flush).
    // The dirty-token snapshot is taken under the vault lock, but the network
    // write happens with the lock released; tokens are only cleared after the
    // store confirms success so transient failures are retried next turn.
    let vault_t2 = Arc::clone(&vault_arc);
    let stdout_t2 = Arc::clone(&stdout_arc);
    let store_t2 = store;
    let session_id_t2 = session_id;

    let t2 = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line in reader.lines() {
            let Ok(payload) = line else { break };

            let redacted = {
                let mut v = vault_t2.lock().unwrap();
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

            let mut out = stdout_t2.lock().unwrap();
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

    // Join the child->host reader first (it stops on child EOF), reap the
    // child, and propagate a non-zero child exit code immediately — this
    // avoids blocking on t1 if the child died while host stdin is still open.
    let _ = t2.join();
    match child.wait() {
        Ok(status) if !status.success() => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(_) => {}
        Err(_) => {}
    }
    let _ = t1.join();
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }

        // Untrusted tool call blocked with JSON-RPC -32001 error
        let untrusted_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}}"#;
        match process_inbound_line(untrusted_req, &mut vault, &acl) {
            InboundAction::BlockWithError(err) => {
                assert!(err.contains("-32001"));
                assert!(err.contains("PII exfiltration blocked"));
            }
            InboundAction::Forward(_) => panic!("Untrusted tool call must be blocked"),
        }
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

        // Valid configuration defaults to compact-hash + 3600s TTL.
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
