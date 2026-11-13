use serde_json::Value;
use std::io::{self, BufRead, Write};

/// Builds the mock server's JSON-RPC response for a single request.
fn respond_to_request(val: &Value) -> Option<Value> {
    let method = val.get("method")?.as_str()?;
    let id = val.get("id").cloned().unwrap_or(Value::Null);
    let resp = match method {
        "init_data" => {
            // Seed some initial data containing PII to parent
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "Initial database record created for NIK 3573012203950001"
                        }
                    ]
                }
            })
        }
        "tools/call" => {
            let tool_name = val
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");

            let args = val
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_default();

            match tool_name {
                "query_customer" => {
                    let nik = args.get("nik").and_then(|n| n.as_str()).unwrap_or("");
                    let cpf = args.get("cpf").and_then(|n| n.as_str()).unwrap_or("");
                    let has_token = args.to_string().contains('<');
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "child_saw_token": has_token,
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Customer found with NIK: {}, CPF: {}, Mobile: 081234567890", nik, cpf)
                                }
                            ]
                        }
                    })
                }
                _ => {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": "Default OK"}]
                        }
                    })
                }
            }
        }
        _ => return None,
    };
    Some(resp)
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };

        match val {
            // JSON-RPC batch: one response element per request element.
            Value::Array(batch) => {
                let responses: Vec<Value> =
                    batch.iter().filter_map(respond_to_request).collect();
                if !responses.is_empty() {
                    let _ = writeln!(stdout, "{}", Value::Array(responses));
                    let _ = stdout.flush();
                }
            }
            _ => {
                if let Some(resp) = respond_to_request(&val) {
                    let _ = writeln!(stdout, "{}", resp);
                    let _ = stdout.flush();
                }
            }
        }
    }
}
