use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_mcp_proxy_stdio_process_lifecycle_e2e() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");

    // Spawn proxy wrapping mock child MCP server over OS pipes
    let mut proxy_proc = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--")
        .arg(mock_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn pii-mcp-proxy process");

    let mut proxy_stdin = proxy_proc.stdin.take().expect("Child stdin accessible");
    let mut proxy_stdout_reader =
        BufReader::new(proxy_proc.stdout.take().expect("Child stdout accessible"));

    let mut line_buf = String::new();

    // 1. Seed initial database data containing raw NIK
    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"init_data"}"#;
    writeln!(proxy_stdin, "{}", init_req).unwrap();
    proxy_stdin.flush().unwrap();

    line_buf.clear();
    proxy_stdout_reader.read_line(&mut line_buf).unwrap();
    assert!(
        line_buf.contains("<ID_NIK_1>"),
        "Proxy outbound must redact NIK in child response, got: {}",
        line_buf
    );
    assert!(!line_buf.contains("3573012203950001"));

    // 2. Client calls trusted tool 'query_customer' using token <ID_NIK_1>
    let trusted_tool_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_customer","arguments":{"nik":"<ID_NIK_1>"}}}"#;
    writeln!(proxy_stdin, "{}", trusted_tool_req).unwrap();
    proxy_stdin.flush().unwrap();

    line_buf.clear();
    proxy_stdout_reader.read_line(&mut line_buf).unwrap();

    // The child saw raw NIK 3573012203950001, echoed it, and proxy re-redacted it to <ID_NIK_1>
    assert!(
        line_buf.contains("<ID_NIK_1>"),
        "Outbound must retain token continuity for NIK, got: {}",
        line_buf
    );
    // Newly returned mobile phone from child must be redacted to <PHONE_ID_1>
    assert!(
        line_buf.contains("<PHONE_ID_1>"),
        "Outbound must redact newly discovered phone, got: {}",
        line_buf
    );
    assert!(!line_buf.contains("081234567890"));

    // 3. Client calls untrusted tool 'untrusted_search' attempting to exfiltrate token <ID_NIK_1>
    let untrusted_req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"untrusted_search","arguments":{"query":"<ID_NIK_1>"}}}"#;
    writeln!(proxy_stdin, "{}", untrusted_req).unwrap();
    proxy_stdin.flush().unwrap();

    line_buf.clear();
    proxy_stdout_reader.read_line(&mut line_buf).unwrap();
    assert!(
        line_buf.contains("-32001"),
        "Proxy must block untrusted tool call with -32001, got: {}",
        line_buf
    );
    assert!(line_buf.contains("PII exfiltration blocked"));

    // 4. Client closes stdin to trigger EOF and clean child shutdown
    drop(proxy_stdin);

    let status = proxy_proc
        .wait()
        .expect("Proxy must terminate cleanly on EOF");
    assert!(status.success(), "Proxy process must exit with code 0");
}
