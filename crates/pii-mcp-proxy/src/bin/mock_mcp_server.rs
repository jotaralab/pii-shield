use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };

        if let Some(method) = val.get("method").and_then(|m| m.as_str()) {
            let id = val.get("id").cloned().unwrap_or(serde_json::Value::Null);
            match method {
                "init_data" => {
                    // Seed some initial data containing PII to parent
                    let resp = serde_json::json!({
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
                    });
                    let _ = writeln!(stdout, "{}", resp);
                    let _ = stdout.flush();
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

                    let resp = match tool_name {
                        "query_customer" => {
                            let nik = args.get("nik").and_then(|n| n.as_str()).unwrap_or("");
                            serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("Customer found with NIK: {}, Mobile: 081234567890", nik)
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
                    };

                    let _ = writeln!(stdout, "{}", resp);
                    let _ = stdout.flush();
                }
                _ => {}
            }
        }
    }
}
