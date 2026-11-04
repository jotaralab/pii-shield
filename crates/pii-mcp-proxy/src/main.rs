use pii_core::{PiiCatalog, PiiSessionVault, SecurityError, TokenFormat, ToolTrustLevel};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

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
pub fn process_inbound_line(line: &str, vault: &PiiSessionVault, acl: &ToolAcl) -> InboundAction {
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
    vault: &PiiSessionVault,
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
            if let Some(args) = params.get_mut("arguments") {
                match vault.rehydrate_json_value(args, trust_level) {
                    Ok(()) => {}
                    Err(SecurityError::ExfiltrationBlocked { token }) => {
                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id_val,
                            "error": {
                                "code": -32001,
                                "message": "PII exfiltration blocked for untrusted tool",
                                "data": { "token": token }
                            }
                        });
                        return Some(InboundAction::BlockWithError(err_resp.to_string()));
                    }
                    Err(err) => {
                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id_val,
                            "error": {
                                "code": -32002,
                                "message": err.to_string(),
                            }
                        });
                        return Some(InboundAction::BlockWithError(err_resp.to_string()));
                    }
                }
            }
        }
    }
    None
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

pub struct ProxyConfig {
    pub trusted_tools: Vec<String>,
    pub trust_all: bool,
    pub locales: Vec<String>,
    pub rules_files: Vec<String>,
    pub token_format: ProxyTokenFormat,
    pub stdio_filter: bool,
    pub session_key: Option<[u8; 32]>,
    pub child_cmd: Option<(String, Vec<String>)>,
}

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
        if token_format != Some(ProxyTokenFormat::StatelessSealed) {
            return Err(format!(
                "{} requires --token-format stateless-sealed (stateful tokens cannot be generated in filter mode)",
                mode_name
            ));
        }
        if session_key.is_none() {
            return Err(format!(
                "{} with stateless-sealed tokens requires PII_SHIELD_SESSION_KEY",
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
    -h, --help                 Show this help
    -V, --version              Show version

ENVIRONMENT:
    PII_SHIELD_SESSION_KEY     64-char hex (32 bytes) shared session key
    PII_SHIELD_TOKEN_FORMAT    Alias for --token-format
    PII_SHIELD_STATELESS=1     Alias for --token-format stateless-sealed

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

    let vault = match build_vault(&config) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("pii-mcp-proxy error: {}", msg);
            eprintln!("Run with --help for usage.");
            std::process::exit(2);
        }
    };

    let acl = ToolAcl::new(config.trusted_tools.clone(), config.trust_all);

    // Filter mode if no child command specified
    if config.stdio_filter || config.child_cmd.is_none() {
        let stdin = io::stdin();
        let stdout = Arc::new(Mutex::new(io::stdout()));

        for line in stdin.lock().lines() {
            let Ok(payload) = line else { break };
            match process_inbound_line(&payload, &vault, &acl) {
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

    // Thread 1: Host stdin -> Child stdin (with exfiltration check)
    let vault_t1 = Arc::clone(&vault_arc);
    let stdout_t1 = Arc::clone(&stdout_arc);

    let t1 = thread::spawn(move || {
        let stdin = io::stdin();
        let mut child_writer = io::BufWriter::new(child_stdin);

        for line in stdin.lock().lines() {
            let Ok(payload) = line else { break };
            let action = {
                let v = vault_t1.lock().unwrap();
                process_inbound_line(&payload, &v, &acl)
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

    // Thread 2: Child stdout -> Host stdout (with redaction)
    let vault_t2 = Arc::clone(&vault_arc);
    let stdout_t2 = Arc::clone(&stdout_arc);

    let t2 = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line in reader.lines() {
            let Ok(payload) = line else { break };
            let redacted = {
                let mut v = vault_t2.lock().unwrap();
                process_outbound_line(&payload, &mut v)
            };

            let mut out = stdout_t2.lock().unwrap();
            let _ = writeln!(out, "{}", redacted);
            let _ = out.flush();
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
        match process_inbound_line(trusted_req, &vault, &acl) {
            InboundAction::Forward(fw) => {
                assert!(fw.contains("3573012203950001"));
            }
            InboundAction::BlockWithError(_) => panic!("Trusted tool must not be blocked"),
        }

        // Untrusted tool call blocked with JSON-RPC -32001 error
        let untrusted_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"<ID_NIK_1>"}}}"#;
        match process_inbound_line(untrusted_req, &vault, &acl) {
            InboundAction::BlockWithError(err) => {
                assert!(err.contains("-32001"));
                assert!(err.contains("PII exfiltration blocked"));
            }
            InboundAction::Forward(_) => panic!("Untrusted tool call must be blocked"),
        }
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
