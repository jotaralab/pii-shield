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

fn write_temp_rules_file(content: &str, name: &str) -> TempRulesFile {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "pii_shield_test_{}_{}_{}_{}.toml",
        name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, content).expect("Write temp rules file");
    TempRulesFile { path }
}

/// RAII guard deleting the temp .toml on drop (even on assertion panic).
struct TempRulesFile {
    path: std::path::PathBuf,
}

impl std::ops::Deref for TempRulesFile {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempRulesFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

    // Cross-process session-key + custom-rule adoption proof:
    // Proxy A (child mode, stateless-sealed + key) redacts raw PII into
    // self-contained sealed tokens; proxy B (--stdio-filter, same key) must
    // decrypt them. If either process ignored PII_SHIELD_SESSION_KEY, token
    // generation/decryption would use an OS-random key and this test fails.
    let mut proxy_a = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--rules-file")
        .arg(rules_path.to_str().unwrap())
        .arg("--token-format")
        .arg("stateless-sealed")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--")
        .arg(mock_bin)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Spawn proxy A");

    let mut stdin = proxy_a.stdin.take().expect("stdin");
    let mut reader = BufReader::new(proxy_a.stdout.take().expect("stdout"));

    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001","cpf":"123.456.789-00"}}}}}}"#
    );
    stdin.flush().unwrap();

    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();
    assert!(
        !buf.contains("3573012203950001") && !buf.contains("123.456.789-00"),
        "Raw PII must not leak externally: {}",
        buf
    );
    let nik_sealed = extract_sealed(&buf, "ID_NIK");
    let cpf_sealed = extract_sealed(&buf, "BR_CPF");
    assert!(
        nik_sealed.is_some() && cpf_sealed.is_some(),
        "Built-in + custom rules must both seal under the env session key: {}",
        buf
    );

    drop(stdin);
    let status = proxy_a.wait().unwrap();
    assert!(status.success());

    // Proxy B: filter mode, --locales none + only the custom rules file
    // (isolated catalog), same key. Sliding sealed tokens in through a
    // trusted tool must decrypt across the process boundary.
    let mut proxy_b = Command::new(proxy_bin)
        .arg("--stdio-filter")
        .arg("--token-format")
        .arg("stateless-sealed")
        .arg("--locales")
        .arg(format!("none,{}", rules_path.to_str().unwrap()))
        .arg("--trusted-tools")
        .arg("query_nik")
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Spawn proxy B");

    let mut stdin_b = proxy_b.stdin.take().expect("stdin");
    let mut reader_b = BufReader::new(proxy_b.stdout.take().expect("stdout"));

    let _ = writeln!(
        stdin_b,
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"query_nik","arguments":{{"nik":"{}","cpf":"{}"}}}}}}"#,
        nik_sealed.unwrap(),
        cpf_sealed.unwrap()
    );
    stdin_b.flush().unwrap();

    buf.clear();
    reader_b.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("3573012203950001"),
        "Proxy B must decrypt sealed NIK token cross-process (key ignored?): {}",
        buf
    );
    let _ = &reader_b;
    assert!(
        buf.contains("123.456.789-00"),
        "Proxy B must decrypt sealed custom-rule token cross-process: {}",
        buf
    );

    drop(stdin_b);
    let status = proxy_b.wait().unwrap();
    assert!(status.success());
}

/// Extracts the first <PII:{prefix}:HEX> sealed token from a line.
fn extract_sealed(buf: &str, prefix: &str) -> Option<String> {
    let needle = format!("<PII:{}:", prefix);
    let start = buf.find(&needle)?;
    let end = buf[start..].find('>')? + start;
    Some(buf[start..=end].to_string())
}

#[test]
fn test_untrusted_exfiltration_blocking_on_custom_rules() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");
    let rules_path = write_temp_rules_file(CPF_TOML, "cpf_exfil");

    let mut proxy_proc = Command::new(proxy_bin)
        .arg("--locales")
        .arg("none")
        .arg("--rules-file")
        .arg(rules_path.to_str().unwrap())
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
    let mut buf = String::new();

    // 1. Outbound redaction: --locales none must activate ONLY the custom
    //    rule while leaving built-in NIK/PHONE rules unloaded.
    //    (Trusted tool so inbound raw PII rehydration passes through; the raw
    //    echo back is redacted outbound into sequential tokens.)
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001","cpf":"123.456.789-00"}}}}}}"#
    );
    stdin.flush().unwrap();
    reader.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("<BR_CPF_1>") && !buf.contains("123.456.789-00"),
        "--locales none + --rules-file must isolate to custom rules and still redact: {}",
        buf
    );
    assert!(
        buf.contains("3573012203950001") && !buf.contains("<ID_NIK"),
        "-locale none must suppress built-in NIK redaction while keeping the custom rule: {}",
        buf
    );
    assert!(
        buf.contains("081234567890") && !buf.contains("<PHONE_ID"),
        "--locales none must leave built-in PHONE_ID rules unloaded: {}",
        buf
    );

    // 2. Untrusted tool call replaying <BR_CPF_1> must be blocked (-32001).
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"untrusted_search","arguments":{{"q":"<BR_CPF_1>"}}}}}}"#
    );
    stdin.flush().unwrap();
    buf.clear();
    reader.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("-32001") && buf.contains("PII exfiltration blocked"),
        "Untrusted replay of custom-rule token must be blocked: {}",
        buf
    );

    drop(stdin);
    let status = proxy_proc.wait().unwrap();
    assert!(status.success());
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
    let token_end = buf[idx..]
        .find('>')
        .map(|e| idx + e)
        .expect("Token terminator");
    let token_full = buf[token_start..=token_end].to_string();
    let body = &token_full["<ID_NIK_".len()..token_full.len() - 1];
    assert_ne!(
        body, "1",
        "Compact-hash must not be sequential: {}",
        token_full
    );
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
        buf.contains(r#""child_saw_token":false"#),
        "Compact-hash tokens must rehydrate in trusted calls: {}",
        buf
    );
    assert!(
        buf.contains(token_full.as_str()),
        "Token continuity must be preserved outbound: {}",
        buf
    );

    drop(stdin);
    let status = proxy_proc.wait().unwrap();
    assert!(status.success(), "Proxy must exit cleanly");
}

#[test]
fn test_fail_closed_exit_code_2() {
    // Unknown locale
    let (stderr, code) = spawn_err_proxy(&["--locales", "global_typo"], vec![]);
    assert_eq!(code, 2, "unknown locale must exit 2 (stderr: {})", stderr);
    assert!(stderr.contains("Unknown locale"), "stderr: {}", stderr);
    assert!(!stderr.contains("running"), "stderr: {}", stderr);

    // 'none' with no rules file -> 0 rules fail-closed (reaches build_vault
    // by passing a child command; otherwise implicit filter mode rejects first)
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");
    let (stderr, code) = spawn_err_proxy(&["--locales", "none", "--", mock_bin], vec![]);
    assert_eq!(code, 2, "empty catalog must exit 2 (stderr: {})", stderr);
    assert!(stderr.contains("0 rules"), "stderr: {}", stderr);

    // Missing rules file (child command needed to pass filter-mode validation)
    let (stderr, code) = spawn_err_proxy(
        &["--rules-file", "/nonexistent/rules.toml", "--", mock_bin],
        vec![],
    );
    assert_eq!(code, 2);
    assert!(
        stderr.contains("Cannot read rules file"),
        "stderr: {}",
        stderr
    );

    // Malformed regex in rules file
    let bad_path = write_temp_rules_file(BAD_REGEX_TOML, "bad_regex");
    let (stderr, code) = spawn_err_proxy(
        &["--rules-file", bad_path.to_str().unwrap(), "--", mock_bin],
        vec![],
    );
    assert_eq!(code, 2, "invalid regex must exit 2 (stderr: {})", stderr);
    assert!(
        stderr.contains("Invalid regex for rule BAD_RE"),
        "stderr: {}",
        stderr
    );

    // Invalid hex session key
    let (stderr, code) = spawn_err_proxy(&[], vec![("PII_SHIELD_SESSION_KEY", "not-hex!")]);
    assert_eq!(code, 2, "invalid key must exit 2 (stderr: {})", stderr);
    assert!(
        stderr.contains("PII_SHIELD_SESSION_KEY"),
        "stderr: {}",
        stderr
    );

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
    assert!(stderr.contains("stateless-sealed"), "stderr: {}", stderr);

    // stdio-filter without stateless-sealed (stateful tokens unusable there)
    let (stderr, code) = spawn_err_proxy(&["--stdio-filter"], vec![]);
    assert_eq!(code, 2);
    assert!(stderr.contains("stateless-sealed"), "stderr: {}", stderr);

    // stdio-filter combined with a child command
    let (_, code) = spawn_err_proxy(
        &[
            "--stdio-filter",
            "--token-format",
            "stateless-sealed",
            "true",
            "/bin/true",
        ],
        vec![],
    );
    assert_eq!(code, 2);

    // Bare trailing '--' with no child command
    let (stderr, code) = spawn_err_proxy(&["--"], vec![]);
    assert_eq!(code, 2);
    assert!(stderr.contains("child command"), "stderr: {}", stderr);

    // Missing flag value: next flag must not be swallowed as the value
    let (stderr, code) = spawn_err_proxy(&["--trusted-tools", "--stdio-filter"], vec![]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("Missing value for flag '--trusted-tools'"),
        "stderr: {}",
        stderr
    );

    // stateless-sealed without a child command and without a key
    let (stderr, code) = spawn_err_proxy(&["--token-format", "stateless-sealed"], vec![]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("PII_SHIELD_SESSION_KEY"),
        "stderr: {}",
        stderr
    );

    // Invalid PII_SHIELD_STATELESS value
    let (stderr, code) = spawn_err_proxy(&[], vec![("PII_SHIELD_STATELESS", "bogus")]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("PII_SHIELD_STATELESS"),
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

    // Implicit filter mode (no child command, no stateless config) is rejected
    let (stderr, code) = spawn_err_proxy(&[], vec![]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("stateless-sealed"),
        "Implicit filter mode must require stateless-sealed tokens: {}",
        stderr
    );

    // Stateless-sealed still requires the env key in implicit filter mode
    let (stderr, code) = spawn_err_proxy(&["--token-format", "stateless-sealed"], vec![]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("PII_SHIELD_SESSION_KEY"),
        "stderr: {}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// Multi-pod E2E: shared RESP (Valkey/Redis) store
// ---------------------------------------------------------------------------

/// Extracts the first `<ID_NIK_...>` token from a line.
fn extract_nik_token(buf: &str) -> String {
    let start = buf.find("<ID_NIK_").expect("NIK token present");
    let end = buf[start..].find('>').expect("token terminator") + start;
    buf[start..=end].to_string()
}

#[test]
fn test_multi_pod_shared_valkey_store() {
    use pii_store_redis::test_support::MockValkey;
    use std::io::BufRead;
    use std::time::{Duration, Instant};

    let key_hex = "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb";
    let session = "shared-session-1";
    let hash_key = format!("pii:v1:{}", session);
    let valkey = MockValkey::start();
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");

    // --- Pod B starts first and boots against an empty store ---
    let mut pod_b = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--valkey-url")
        .arg(valkey.url())
        .arg("--session-id")
        .arg(session)
        .arg("--")
        .arg(mock_bin)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn pod B");
    let mut stdin_b = pod_b.stdin.take().unwrap();
    let mut reader_b = BufReader::new(pod_b.stdout.take().unwrap());

    // Wait until Pod B's mandatory startup HGETALL has been served while the
    // store is still empty, so it cannot rely on startup hydration below.
    let deadline = Instant::now() + Duration::from_secs(5);
    while valkey.command_count("hgetall") == 0 {
        assert!(
            Instant::now() < deadline,
            "Pod B never performed its startup HGETALL"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(valkey.entry_count(&hash_key), 0);

    // --- Pod A starts while Pod B is live: redact + persist ---
    let mut pod_a = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--valkey-url")
        .arg(valkey.url())
        .arg("--session-id")
        .arg(session)
        .arg("--session-ttl")
        .arg("120")
        .arg("--")
        .arg(mock_bin)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn pod A");
    let mut stdin_a = pod_a.stdin.take().unwrap();
    let mut reader_a = BufReader::new(pod_a.stdout.take().unwrap());
    writeln!(
        stdin_a,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001"}}}}}}"#
    )
    .unwrap();
    stdin_a.flush().unwrap();
    let mut line = String::new();
    reader_a.read_line(&mut line).unwrap();
    assert!(
        !line.contains("3573012203950001"),
        "Pod A outbound must redact raw NIK: {}",
        line
    );
    let token = extract_nik_token(&line);

    // The atomic write must have been observed: MULTI/HSET/EXPIRE/EXEC and
    // the configured TTL, not just an in-memory redaction.
    assert!(
        valkey.entry_count(&hash_key) >= 1,
        "Pod A must persist the sealed NIK entry"
    );
    assert_eq!(
        valkey.ttl(&hash_key),
        Some(120),
        "Pod A must apply the configured session TTL"
    );
    assert!(valkey.command_count("multi") >= 1, "MULTI must be used");
    assert!(
        valkey.command_count("hset") + valkey.command_count("hmset") >= 1,
        "HSET/HMSET must be used"
    );
    assert!(valkey.command_count("expire") >= 1, "EXPIRE must be used");
    assert!(valkey.command_count("exec") >= 1, "EXEC must be used");

    drop(stdin_a);
    assert!(pod_a.wait().unwrap().success());

    // --- Pod B: dynamic inbound hydration (startup snapshot was empty) ---
    writeln!(
        stdin_b,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"{}"}}}}}}"#,
        token
    )
    .unwrap();
    stdin_b.flush().unwrap();
    let mut line_b = String::new();
    reader_b.read_line(&mut line_b).unwrap();
    assert!(
        line_b.contains(r#""child_saw_token":false"#),
        "Pod B must hydrate the token dynamically on inbound tools/call: {}",
        line_b
    );

    writeln!(
        stdin_b,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"web_search","arguments":{{"q":"{}"}}}}}}"#,
        token
    )
    .unwrap();
    stdin_b.flush().unwrap();
    line_b.clear();
    reader_b.read_line(&mut line_b).unwrap();
    assert!(
        line_b.contains("-32001"),
        "Pod B must block untrusted exfiltration using hydrated state: {}",
        line_b
    );

    drop(stdin_b);
    assert!(pod_b.wait().unwrap().success(), "Pod B must exit cleanly");
}

#[test]
fn test_valkey_outbound_failure_retries_on_next_turn() {
    use pii_store_redis::test_support::MockValkey;
    use std::io::BufRead;

    let key_hex = "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb";
    let session = "retry-session-1";
    let hash_key = format!("pii:v1:{}", session);
    // First EXEC is aborted, so turn 1's tokens stay dirty; turn 2 retries.
    let valkey = MockValkey::start_failing_first_exec();
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");

    let mut proxy = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--valkey-url")
        .arg(valkey.url())
        .arg("--session-id")
        .arg(session)
        .arg("--")
        .arg(mock_bin)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn proxy");
    let mut stdin = proxy.stdin.take().unwrap();
    let mut reader = BufReader::new(proxy.stdout.take().unwrap());

    // Turn 1: outbound redaction creates a token, but the store write fails
    // (first EXEC aborted), so nothing may be reported as persisted.
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"init_data"}}"#).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.contains("<ID_NIK_") && !line.contains("3573012203950001"),
        "turn 1 must redact NIK: {}",
        line
    );
    assert_eq!(
        valkey.entry_count(&hash_key),
        0,
        "aborted EXEC must not persist any entry"
    );

    // Turn 2: the retained dirty token is flushed before the inbound tool call
    // and the retried EXEC succeeds.
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001"}}}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(
        valkey.entry_count(&hash_key) >= 1,
        "dirty token must be retried and persisted on turn 2"
    );
    assert!(
        valkey.command_count("exec") >= 2,
        "first EXEC must fail and the second must succeed"
    );

    drop(stdin);
    assert!(proxy.wait().unwrap().success(), "proxy must exit cleanly");
}

#[test]
fn test_valkey_outage_during_tools_call_fails_closed() {
    use pii_store_redis::test_support::MockValkey;
    use std::io::BufRead;

    let key_hex = "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb";
    let valkey = MockValkey::start_with(false);
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");

    let mut proxy = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--trusted-tools")
        .arg("query_customer")
        .arg("--valkey-url")
        .arg(valkey.url())
        .arg("--session-id")
        .arg("outage-session")
        .arg("--")
        .arg(mock_bin)
        .env("PII_SHIELD_SESSION_KEY", key_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn proxy");

    let mut stdin = proxy.stdin.take().unwrap();
    let mut reader = BufReader::new(proxy.stdout.take().unwrap());

    // The mock served the startup HGETALL then closed the listener and socket.
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"3573012203950001"}}}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.contains("-32003"),
        "Store outage during tools/call must fail closed with -32003: {}",
        line
    );
    assert!(line.contains("PII vault store synchronization failed"));

    drop(stdin);
    assert!(proxy.wait().unwrap().success(), "proxy must exit cleanly");
}

#[test]
fn test_valkey_unreachable_at_startup_exits_2() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("redis://{}", addr);

    let (stderr, code) = spawn_err_proxy(
        &[
            "--valkey-url",
            &url,
            "--session-id",
            "startup-failure",
            "--",
            env!("CARGO_BIN_EXE_mock_mcp_server"),
        ],
        vec![(
            "PII_SHIELD_SESSION_KEY",
            "0123456789abcdeffedcba9876543210feedface00112233445566778899aabb",
        )],
    );
    assert_eq!(
        code, 2,
        "unreachable store must exit 2 (stderr: {})",
        stderr
    );
    assert!(
        stderr.contains("initial vault store load failed"),
        "stderr: {}",
        stderr
    );
}

/// Regression: blocked batch elements must produce their error responses on
/// the host (proxy stdout), not on the child's stdin. Allowed elements are
/// still forwarded to the child (mixed batches are split across channels).
#[test]
fn test_batch_blocked_errors_reach_host_not_child() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");
    let mock_bin = env!("CARGO_BIN_EXE_mock_mcp_server");

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
        .expect("Spawn proxy");

    let mut stdin = proxy_proc.stdin.take().expect("stdin");
    let mut reader = BufReader::new(proxy_proc.stdout.take().expect("stdout"));
    let mut buf = String::new();

    // Seed a token by triggering outbound redaction.
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"init_data"}}"#
    );
    stdin.flush().unwrap();
    reader.read_line(&mut buf).unwrap();
    assert!(buf.contains("<ID_NIK_1>"), "seed response: {}", buf);

    // Mixed batch: one blocked (untrusted exfil), one allowed (trusted tool).
    buf.clear();
    let _ = writeln!(
        stdin,
        r#"[{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"untrusted_search","arguments":{{"q":"<ID_NIK_1>"}}}}}},{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"query_customer","arguments":{{"nik":"<ID_NIK_1>"}}}}}}]"#
    );
    stdin.flush().unwrap();

    // First line from the host must be the per-element error array (id 2),
    // NOT a forward of the whole batch to the child.
    reader.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("-32001"),
        "blocked batch error must reach the host, got: {}",
        buf
    );
    assert!(
        !buf.contains("\"result\"") || buf.contains("-32001"),
        "host must not receive the child's forwarded response in the error line: {}",
        buf
    );

    // The allowed element is still forwarded to the child, which responds.
    buf.clear();
    reader.read_line(&mut buf).unwrap();
    assert!(
        buf.contains("\"id\":3") && buf.contains("<ID_NIK_1>"),
        "allowed batch element must still be processed by the child, got: {}",
        buf
    );

    drop(stdin);
    let status = proxy_proc.wait().unwrap();
    assert!(status.success());
}

/// Regression: if the child MCP server exits while the host keeps its stdin
/// open, the proxy must still terminate (no deadlock on the blocked stdin
/// read in thread 1).
#[test]
fn test_child_exit_does_not_deadlock_while_host_stdin_open() {
    let proxy_bin = env!("CARGO_BIN_EXE_pii-mcp-proxy");

    let mut proxy_proc = Command::new(proxy_bin)
        .arg("--locales")
        .arg("global,id")
        .arg("--")
        .arg("/bin/true") // exits immediately
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Spawn proxy");

    // Deliberately keep the host's stdin open: thread 1 blocks on read(0).
    let _stdin = proxy_proc.stdin.take().expect("stdin");

    let (tx, rx) = std::sync::mpsc::channel();
    let _watcher = std::thread::spawn(move || {
        let status = proxy_proc.wait().expect("wait proxy");
        let _ = tx.send(status);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(status) => {
            assert!(
                status.success() || status.code().is_some(),
                "proxy exited cleanly after child death"
            );
        }
        Err(_) => panic!("proxy deadlocked after child exit while host stdin stayed open"),
    }
}
