use pii_core::{
    InMemoryVaultStore, PiiSessionVault, SecurityError, SecurityPolicy, StreamingRehydrator,
    TokenFormat, ToolTrustLevel,
};

#[test]
fn test_distributed_agent_lifecycle_e2e_compact_hash() {
    let cluster_key = [101u8; 32];
    let session_id = "agent_session_ord_442";
    let mut distributed_kv = InMemoryVaultStore::new();

    // =========================================================================
    // TURN 1: Ingress Gateway (Pod A)
    // =========================================================================
    let mut pod_a = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
    pod_a.set_token_format(TokenFormat::CompactHash);

    let user_prompt = "Tolong periksa tagihan Kartu Kredit 4532015112830366 dan NIK 3573012203950001, kirim ke budi.santoso@gmail.com";
    let masked_prompt = pod_a.redact(user_prompt);

    assert!(masked_prompt.contains("<CREDIT_CARD_"));
    assert!(masked_prompt.contains("<ID_NIK_"));
    assert!(masked_prompt.contains("<EMAIL_"));
    assert!(!masked_prompt.contains("4532015112830366"));
    assert!(!masked_prompt.contains("3573012203950001"));
    assert!(!masked_prompt.contains("budi.santoso@gmail.com"));

    // Extract generated tokens
    let nik_token = masked_prompt
        .split_whitespace()
        .find(|w| w.starts_with("<ID_NIK_"))
        .unwrap()
        .trim_end_matches(',');
    let card_token = masked_prompt
        .split_whitespace()
        .find(|w| w.starts_with("<CREDIT_CARD_"))
        .unwrap();
    let email_token = masked_prompt
        .split_whitespace()
        .find(|w| w.starts_with("<EMAIL_"))
        .unwrap();

    // Pod A flushes dirty entries to distributed KV store (HSET)
    let flushed_count = pod_a
        .flush_to_store(&mut distributed_kv, session_id)
        .unwrap();
    assert_eq!(flushed_count, 3);

    // Pod A terminates (crash / scale down / ephemeral worker drop)
    drop(pod_a);

    // =========================================================================
    // TURN 2: Tool Runner Worker (Pod B)
    // =========================================================================
    let mut pod_b = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
    pod_b.set_token_format(TokenFormat::CompactHash);

    // Pod B starts with empty RAM, pulls state from distributed KV
    pod_b.load_from_store(&distributed_kv, session_id).unwrap();

    // LLM decides to call trusted internal database tool
    let tool_call_json = format!(
        r#"{{"customer_nik":"{}","card_number":"{}"}}"#,
        nik_token, card_token
    );

    let rehydrated_args = pod_b
        .rehydrate_for_tool(&tool_call_json, ToolTrustLevel::InternalTrusted)
        .expect("Trusted tool call must rehydrate successfully");

    assert!(rehydrated_args.contains(r#""customer_nik":"3573012203950001""#));
    assert!(rehydrated_args.contains(r#""card_number":"4532015112830366""#));

    // Internal database executes and returns JSON with existing NIK and NEW Phone
    let mock_db_result = r#"{"status":"active","customer_nik":"3573012203950001","phone":"081234567890","balance":1500000}"#;

    // Pod B redacts tool output before feeding back to LLM context
    let masked_tool_result = pod_b.redact_json(mock_db_result);

    // Entity continuity: existing NIK MUST keep its original token
    assert!(masked_tool_result.contains(&format!(r#""customer_nik":"{}""#, nik_token)));
    // Newly discovered Phone must be masked with a new token
    assert!(masked_tool_result.contains(r#""phone":"<PHONE_ID_"#));
    // Unquoted numbers must remain uncorrupted numbers
    assert!(masked_tool_result.contains(r#""balance":1500000"#));

    // Pod B flushes newly minted phone entry to distributed KV
    let flushed_delta = pod_b
        .flush_to_store(&mut distributed_kv, session_id)
        .unwrap();
    assert_eq!(flushed_delta, 1);

    // =========================================================================
    // TURN 3: Exfiltration Defense on Untrusted External Tool
    // =========================================================================
    // LLM attempts to send NIK token to untrusted web search tool
    let untrusted_tool_call = format!(r#"{{"query":"search {} on public web"}}"#, nik_token);
    let blocked_err =
        pod_b.rehydrate_for_tool(&untrusted_tool_call, ToolTrustLevel::ExternalUntrusted);
    assert!(matches!(
        blocked_err,
        Err(SecurityError::ExfiltrationBlocked { .. })
    ));

    // Pod B drops
    drop(pod_b);

    // =========================================================================
    // TURN 4: SSE Streaming Egress Proxy (Pod C)
    // =========================================================================
    let mut pod_c = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
    pod_c.load_from_store(&distributed_kv, session_id).unwrap();

    // Retrieve phone token from Pod C
    let phone_token = pod_c.rehydrate_token("3573012203950001");
    assert!(phone_token.is_none()); // reverse_map is token -> raw
    assert_eq!(pod_c.rehydrate(nik_token), "3573012203950001");

    let full_llm_response = format!(
        "Yth. Nasabah, tagihan kartu {} berhasil diproses untuk NIK {}. Notifikasi dikirim ke {}. <div class=\"footer\">© 2026 PT Bank Aman</div>",
        card_token, nik_token, email_token
    );

    // Simulate SSE streaming arriving in tiny 1-3 byte chunk slices
    let mut rehydrator = StreamingRehydrator::new();
    let mut streamed_output = String::new();

    let chars: Vec<char> = full_llm_response.chars().collect();
    let mut idx = 0;
    while idx < chars.len() {
        let step = (idx % 3) + 1;
        let end = (idx + step).min(chars.len());
        let chunk_slice: String = chars[idx..end].iter().collect();
        let rehydrated_chunk = rehydrator.push_chunk(&chunk_slice, &pod_c);
        streamed_output.push_str(&rehydrated_chunk);
        idx = end;
    }
    let flushed = rehydrator.flush(&pod_c);
    streamed_output.push_str(&flushed);

    // Verify final stream contains 100% accurate raw PII and intact HTML
    assert!(streamed_output.contains("4532015112830366"));
    assert!(streamed_output.contains("3573012203950001"));
    assert!(streamed_output.contains("budi.santoso@gmail.com"));
    assert!(streamed_output.contains(r#"<div class="footer">© 2026 PT Bank Aman</div>"#));
    assert!(!streamed_output.contains("<CREDIT_CARD_"));
    assert!(!streamed_output.contains("<ID_NIK_"));
    assert!(!streamed_output.contains("<EMAIL_"));
}

#[test]
fn test_stateless_sealed_mode_distributed_e2e() {
    let cluster_key = [222u8; 32];

    // Ingress Pod
    let mut ingress = PiiSessionVault::with_key(SecurityPolicy::StandardGlobal, cluster_key);
    ingress.set_token_format(TokenFormat::StatelessSealed);

    let raw = "US Citizen SSN 123-45-6789 and IBAN DE89370400440532013000";
    let scrubbed = ingress.redact(raw);
    assert!(scrubbed.contains("<PII:US_SSN:"));
    assert!(scrubbed.contains("<PII:IBAN:"));

    // Egress Pod with zero shared storage
    let egress = PiiSessionVault::with_key(SecurityPolicy::StandardGlobal, cluster_key);
    let restored = egress.rehydrate(&scrubbed);
    assert_eq!(restored, raw);
}
