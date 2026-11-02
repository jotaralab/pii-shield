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

fn write_temp_rules_file(content: &str, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "pii_shield_test_{}_{}.toml",
        name,
        std::process::id()
    ));
    std::fs::write(&path, content).expect("Write temp rules file");
    path
}

const CPF_TOML: &str = r#"
locale = "custom-br"
name = "Custom Brazilian CPF"

[[rules]]
id = "BR_CPF"
tag_prefix = "BR_CPF"
description = "Brazilian CPF"
regex = '\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b'
validator = "none"
priority = 90
context_keywords = ["cpf", "receita", "brasil"]
"#;

const BAD_REGEX_TOML: &str = r#"
locale = "custom-bad"
name = "Bad regex"

[[rules]]
id = "BAD_RE"
tag_prefix = "BAD_RE"
regex = '(unbalanced['
"#;

fn spawn_err_proxy(args: &[&str], envs: Vec<(&str, &str)>) -> (String, i32) {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mut cmd = Command::new(proxy_bin);
    for a in args {
        cmd.arg(a);
    }
    for (k, v) in &envs {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut proc = cmd.spawn().expect("Spawn proxy");
    drop(proc.stdin.take());
    let mut stderr = String::new();
    if let Some(mut se) = proc.stderr.take() {
        use std::io::Read;
        se.read_to_string(&mut stderr).ok();
    }
    let status = proc.wait().expect("Wait for proxy");
    (stderr, status.code().unwrap_or(-1))
}

#[test]
fn test_rules_file_custom_toml_redaction_and_rehydration_with_session_key() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");
    let rules_path = write_temp_rules_file(CPF_TOML, "cpf_valid");
    let key_hex = "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb";

    let mut proxy_proc = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--rules-file")
        .arg(&rules_path)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--")
        .arg(mock_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Spawn proxy");

    let mut stdin = proxy_proc.stdin.take().expect("stdin");
    let mut reader = BufReader::new(proxy_proc.stdout.take().expect("stdout"));

    // 1. Observed tool call with raw values: outbound must redact both the
    //    built-in NIK rule and the custom BR_CPF TOML rule.
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001","cpf":"123.456.789-00"}}}}}}"#
    );
    stdin.flush().unwrap();

    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("<ID_NIK_1>") && buf.contains("<BR_CPF_1>"),
        "Built-in and custom TOML rules must both redact, got: {}",
        buf
    );
    assert!(
        !buf.contains("3573012203950001") && !buf.contains("123.456.789-00"),
        "Raw PII must not leak externally: {}",
        buf
    );

    // 2. Trusted tool call with tokens: proxy must rehydrate them for the
    //    child (child_saw_token=false proves real values reached the child),
    //    then re-redact the echo with token continuity.
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"<ID_NIK_1>","cpf":"<BR_CPF_1>"}}}}}}"#
    );
    stdin.flush().unwrap();

    buf.clear();
    reader.read_line(&mut buf).unwrap();
    assert!(
        !buf.contains(r#""child_saw_token":true"#),
        "Session key + custom rules vault must rehydrate tokens for trusted tools: {}",
        buf
    );
    assert!(
        buf.contains("<ID_NIK_1>") && buf.contains("<BR_CPF_1>"),
        "Re-redacted outbound must preserve token continuity: {}",
        buf
    );
    assert!(
        !buf.contains("3573012203950001") && !buf.contains("123.456.789-00"),
        "Raw PII must not leak back to the host: {}",
        buf
    );

    drop(stdin);
    let status = proxy_proc.wait().unwrap();
    assert!(status.success());

    let _ = std::fs::remove_file(&rules_path);
}

#[test]
fn test_token_format_compact_hash() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");
    let mut proxy_proc = Command::new(proxy_bin)
        .arg("--token-format")
        .arg("compact-hash")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--")
        .arg(mock_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Spawn proxy");

    let mut stdin = proxy_proc.stdin.take().expect("stdin");
    let mut reader = BufReader::new(proxy_proc.stdout.take().expect("stdout"));

    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001"}}}}}}"#
    );
    stdin.flush().unwrap();

    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();

    // Extract the <ID_NIK_XXX> token and verify it is compact-hash (base36
    // suffix, not the sequential "<ID_NIK_1>").
    let idx = buf.find("<ID_NIK_").expect("Token must exist");
    let token_start = idx;
    let token_end = buf[idx..].find('>').map(|e| idx + e).expect("Token terminator");
    let token_full = &buf[token_start..=token_end];
    let body = &token_full["<ID_NIK_".len()..token_full.len() - 1];
    assert_ne!(body, "1", "Compact-hash must not be sequential: {}", token_full);
    assert!(
        body.len() >= 6 && body.bytes().all(|b| b.is_ascii_alphanumeric()),
        "Compact-hash body must be base36 >=6 chars, got <ID_NIK_{}>",
        body
    );
    assert!(
        !buf.contains("3573012203950001"),
        "Raw NIK must not leak: {}",
        buf
    );

    // Rehydration through a trusted tool call with the compact-hash token
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"{}"}}}}}}"#,
        token_full
    );
    stdin.flush().unwrap();

    buf.clear();
    reader.read_line(&mut buf).unwrap();
    assert!(
        !buf.contains(r#""child_saw_token":true"#),
        "Compact-hash tokens must rehydrate in trusted calls: {}",
        buf
    );

    drop(stdin);
    let _ = proxy_proc.wait().unwrap();
}

#[test]
fn test_fail_closed_exit_code_2() {
    // Unknown locale
    let (stderr, code) = spawn_err_proxy(&["--locales", "global_typo"], vec![]);
    assert_eq!(code, 2, "unknown locale must exit 2 (stderr: {})", stderr);
    assert!(stderr.contains("Unknown locale"), "stderr: {}", stderr);
    assert!(!stderr.contains("running"), "stderr: {}", stderr);

    // 'none' with no rules file -> 0 rules fail-closed
    let (stderr, code) = spawn_err_proxy(&["--locales", "none"], vec![]);
    assert_eq!(code, 2, "empty catalog must exit 2 (stderr: {})", stderr);
    assert!(stderr.contains("0 rules"), "stderr: {}", stderr);

    // Missing rules file
    let (stderr, code) = spawn_err_proxy(
        &["--rules-file", "/nonexistent/rules.toml"],
        vec![],
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("Cannot read rules file"), "stderr: {}", stderr);

    // Malformed regex in rules file
    let bad_path = write_temp_rules_file(BAD_REGEX_TOML, "bad_regex");
    let (stderr, code) = spawn_err_proxy(&["--rules-file", bad_path.to_str().unwrap()], vec![]);
    assert_eq!(code, 2, "invalid regex must exit 2 (stderr: {})", stderr);
    assert!(
        stderr.contains("Invalid regex for rule BAD_RE"),
        "stderr: {}",
        stderr
    );
    let _ = std::fs::remove_file(&bad_path);

    // Invalid hex session key
    let (stderr, code) = spawn_err_proxy(&[], vec![("PII_SHIELD_SESSION_KEY", "not-hex!")]);
    assert_eq!(code, 2, "invalid key must exit 2 (stderr: {})", stderr);
    assert!(stderr.contains("PII_SHIELD_SESSION_KEY"), "stderr: {}", stderr);

    // Invalid 64-hex but wrong length session key
    let (code, _) = {
        let (s, c) = spawn_err_proxy(&[], vec![("PII_SHIELD_SESSION_KEY", "aabbccdd")]);
        assert!(s.contains("PII_SHIELD_SESSION_KEY"));
        (c, s)
    };
    assert_eq!(code, 2);

    // Unknown flag
    let (stderr, code) = spawn_err_proxy(&["--definitely-not-real"], vec![]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Unknown argument"), "stderr: {}", stderr);

    // Missing flag argument
    let (_, code) = spawn_err_proxy(&["--locales"], vec![]);
    assert_eq!(code, 2);

    // Empty comma segment
    let (_, code) = spawn_err_proxy(&["--locales", "global,"], vec![]);
    assert_eq!(code, 2);

    // stdio-filter with stateless-sealed and no key
    let (stderr, code) = spawn_err_proxy(
        &["--stdio-filter", "--token-format", "stateless-sealed"],
        vec![],
    );
    assert_eq!(code, 2);
    assert!(
        stderr.contains("stateless-sealed"),
        "stderr: {}",
        stderr
    );

    // Invalid --token-format value
    let (_, code) = spawn_err_proxy(&["--token-format", "bogus"], vec![]);
    assert_eq!(code, 2);

    // Invalid env token format
    let (_, code) = spawn_err_proxy(&[], vec![("PII_SHIELD_TOKEN_FORMAT", "bogus")]);
    assert_eq!(code, 2);

    // --help and --version exit 0
    let (_stderr, code) = spawn_err_proxy(&["--help"], vec![]);
    assert_eq!(code, 0);
    let (_stderr, code) = spawn_err_proxy(&["--version"], vec![]);
    assert_eq!(code, 0);
}
