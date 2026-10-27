use pii_core::{PiiCatalog, PiiSessionVault, SecurityError, ToolTrustLevel};
use serde_json::Value;
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
                vault.redact_json_value(v);
            }
        }
        _ => vault.redact_json_value(&mut val),
    }

    serde_json::to_string(&val).unwrap_or_else(|_| line.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut trusted_tools = Vec::new();
    let mut trust_all = false;
    let mut locales = vec!["global".to_string(), "id".to_string()];
    let mut child_cmd_start = None;
    let mut stdio_filter = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--trusted-tools" => {
                if i + 1 < args.len() {
                    trusted_tools.extend(args[i + 1].split(',').map(|s| s.trim().to_string()));
                    i += 1;
                }
            }
            "--trust-all-tools" => {
                trust_all = true;
            }
            "--locales" => {
                if i + 1 < args.len() {
                    locales = args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    i += 1;
                }
            }
            "--stdio-filter" => {
                stdio_filter = true;
            }
            "--" => {
                if i + 1 < args.len() {
                    child_cmd_start = Some(i + 1);
                }
                break;
            }
            _ => {
                if !args[i].starts_with('-') {
                    child_cmd_start = Some(i);
                    break;
                }
            }
        }
        i += 1;
    }

    let acl = ToolAcl::new(trusted_tools, trust_all);

    // Initialize vault with locales
    let loc_refs: Vec<&str> = locales.iter().map(|s| s.as_str()).collect();
    let catalog = PiiCatalog::with_locales(&loc_refs).unwrap_or_default();
    let mut vault = PiiSessionVault::from_catalog(catalog);

    if let Ok(key_hex) = env::var("PII_SHIELD_SESSION_KEY") {
        if let Ok(key_bytes) = hex::decode(key_hex) {
            if key_bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key_bytes);
                vault =
                    PiiSessionVault::with_key(pii_core::SecurityPolicy::IndonesiaUuPdpStrict, k);
            }
        }
    }

    if env::var("PII_SHIELD_STATELESS").is_ok() {
        vault.set_stateless_mode(true);
    }

    // Filter mode if no child command specified
    if stdio_filter || child_cmd_start.is_none() {
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

    let cmd_idx = child_cmd_start.unwrap();
    let prog = &args[cmd_idx];
    let prog_args = &args[cmd_idx + 1..];

    let mut child = Command::new(prog)
        .args(prog_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn child MCP server");

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

    let _ = t1.join();
    let _ = t2.join();
    let _ = child.wait();
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
