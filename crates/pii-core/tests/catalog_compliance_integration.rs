use pii_core::{PiiCatalog, PiiScanner};

#[test]
fn test_builtin_catalogs_compliance_suite() {
    let locales = ["global", "id", "us", "eu", "sg"];
    let catalog = PiiCatalog::with_locales(&locales).expect("Builtin catalogs must parse cleanly");
    let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner must compile from catalog");

    assert!(
        !catalog.rules.is_empty(),
        "Catalog must contain active rules"
    );

    let mut total_valid = 0usize;
    let mut total_invalid = 0usize;

    for rule in &catalog.rules {
        assert!(
            !rule.valid_samples.is_empty(),
            "Rule '{}' (locale tag '{}') must define at least one valid sample",
            rule.id,
            rule.tag_prefix
        );
        assert!(
            !rule.invalid_samples.is_empty(),
            "Rule '{}' (locale tag '{}') must define at least one invalid sample",
            rule.id,
            rule.tag_prefix
        );

        // 1. Verify all valid samples
        for valid in &rule.valid_samples {
            total_valid += 1;

            if rule.require_context {
                // Context-gated rules (e.g. US_CA_DL) must NOT fire without a
                // context keyword — that is the core anti-SKU guarantee.
                let bare = scanner.scan(valid);
                assert!(
                    !bare
                        .iter()
                        .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix),
                    "require_context sample '{}' must NOT match without context for rule '{}'",
                    valid,
                    rule.id
                );

                // ... and MUST fire for EVERY configured keyword.
                for kw in &rule.context_keywords {
                    assert!(
                        !kw.trim().is_empty(),
                        "Rule '{}' declares require_context with a blank keyword",
                        rule.id
                    );
                    let with_context = format!("{}: {}", kw, valid);
                    let matches_ctx = scanner.scan(&with_context);
                    assert!(
                        matches_ctx
                            .iter()
                            .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix),
                        "Expected valid sample '{}' to match context-gated rule '{}' when prefixed with '{}', got: {:?}",
                        valid,
                        rule.id,
                        kw,
                        matches_ctx
                    );
                    // Invalid samples must ALSO be rejected under context:
                    // otherwise the gate masks regex/checksum defects.
                    for invalid in &rule.invalid_samples {
                        let bad_ctx = format!("{}: {}", kw, invalid);
                        let bad_matches = scanner.scan(&bad_ctx);
                        assert!(
                            !bad_matches
                                .iter()
                                .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix),
                            "Invalid sample '{}' (rule '{}') was accepted under context '{}'",
                            invalid,
                            rule.id,
                            kw
                        );
                    }
                }
            } else {
                // Standalone match
                let matches_standalone = scanner.scan(valid);
                let has_match = matches_standalone
                    .iter()
                    .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix);
                assert!(
                    has_match,
                    "Expected valid sample '{}' to match rule '{}' ({}), but got matches: {:?}",
                    valid, rule.id, rule.tag_prefix, matches_standalone
                );

                // Embedded in realistic conversational sentence
                let sentence = format!("Halo, data akun Anda adalah {} harap simpan.", valid);
                let matches_sentence = scanner.scan(&sentence);
                let sentence_match = matches_sentence
                    .iter()
                    .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix);
                assert!(
                    sentence_match,
                    "Expected valid sample '{}' inside sentence to match rule '{}' ({}), but got matches: {:?}",
                    valid, rule.id, rule.tag_prefix, matches_sentence
                );
            }
        }

        // 2. Verify all invalid samples are rejected
        for invalid in &rule.invalid_samples {
            total_invalid += 1;

            // Standalone rejection
            let matches_standalone = scanner.scan(invalid);
            let false_positive = matches_standalone
                .iter()
                .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix);
            assert!(
                !false_positive,
                "Invalid sample '{}' was incorrectly accepted by rule '{}' ({})",
                invalid, rule.id, rule.tag_prefix
            );

            // Embedded rejection
            let sentence = format!("Nomor referensi acak {} bukan dokumen sah.", invalid);
            let matches_sentence = scanner.scan(&sentence);
            let sentence_false_positive = matches_sentence
                .iter()
                .any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix);
            assert!(
                !sentence_false_positive,
                "Invalid sample '{}' inside sentence was incorrectly accepted by rule '{}' ({})",
                invalid, rule.id, rule.tag_prefix
            );
        }
    }

    println!(
        "Successfully verified {} valid samples and {} invalid samples across {} catalog rules.",
        total_valid,
        total_invalid,
        catalog.rules.len()
    );
}

#[test]
fn test_dynamic_runtime_catalog_extension_e2e() {
    let mut catalog = PiiCatalog::with_locales(&["global"]).expect("Global catalog valid");

    // Dynamic runtime pack for Australian Tax File Number (TFN) format
    let custom_pack_toml = r#"
locale = "au"
name = "Australia (Privacy Act)"

[[rules]]
id = "AU_TFN"
tag_prefix = "AU_TFN"
description = "Australian Tax File Number"
regex = '\b[0-9]{3}[ ]?[0-9]{3}[ ]?[0-9]{3}\b'
validator = "none"
priority = 80
context_keywords = ["tfn", "tax", "ato", "australia"]
valid_samples = ["123 456 789", "987654321"]
invalid_samples = ["123-45", "not-a-number"]
"#;

    catalog
        .merge_toml_str(custom_pack_toml)
        .expect("Custom TOML must merge successfully");

    let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner compiles with custom rule");

    // Verify global rule still works
    let global_matches = scanner.scan("Send report to user@example.com");
    assert!(global_matches
        .iter()
        .any(|m| m.entity_type.as_tag_prefix() == "EMAIL"));

    // Verify custom AU_TFN rule matches
    let au_matches = scanner.scan("Customer ATO TFN: 123 456 789 verified.");
    assert!(au_matches
        .iter()
        .any(|m| m.entity_type.as_tag_prefix() == "AU_TFN"));

    // Verify invalid AU_TFN sample is rejected
    let invalid_matches = scanner.scan("Reference: 123-45 status ok");
    assert!(!invalid_matches
        .iter()
        .any(|m| m.entity_type.as_tag_prefix() == "AU_TFN"));
}

#[test]
fn test_gdpr_ccpa_all_locales_combined_no_cross_collision() {
    let catalog = PiiCatalog::with_locales(&["global", "id", "us", "eu", "sg"])
        .expect("builtin catalogs parse");
    let scanner = PiiScanner::from_catalog(&catalog).expect("scanner compiles");

    // Neutral filler > 48 bytes so the ±48-byte context window of one clause
    // can never bleed into the next. Without this padding, a keyword from a
    // neighbouring clause would inflate a rule's score and mask collisions.
    const PAD: &str =
        " Arbitrary filler prose inserted solely to isolate neighbouring identifiers. ";

    // One combined sentence exercising at least one entity from every locale
    // family: global, id, us, eu, sg — every built-in rule must coexist
    // without false-positive tag collisions.
    let clauses = [
        "Contact user@example.com",
        "Card 4532015112830366",
        "NIK 3573012203950001",
        "NPWP 01.234.567.8-123.000",
        "phone +6281234567890",
        "phone 555-234-5678",
        "SSN 123-45-6789",
        "ITIN 911-70-1234",
        "ABA 121000248",
        "CA driver license A1234567",
        "Steuer-ID 51928327648",
        "NIR 195024610200145",
        "DNI 12345678Z",
        "Codice RSSMRA85M01H501Q",
        "BSN 835030568",
        "PESEL 95022812342",
        "NHS 4139537671",
        "NINO AA123456A",
        "IBAN DE89370400440532013000",
        "+49 30 12345678",
        "NRIC S1234567D",
        "phone +65 8123 4567",
    ];
    let text = clauses.join(PAD);
    let matches = scanner.scan(&text);
    let prefixes: Vec<&str> = matches
        .iter()
        .map(|m| m.entity_type.as_tag_prefix())
        .collect();
    for expected in [
        "EMAIL",
        "CREDIT_CARD",
        "ID_NIK",
        "ID_NPWP",
        "PHONE_ID",
        "PHONE_US",
        "US_SSN",
        "US_ITIN",
        "US_ROUTING_ABA",
        "US_CA_DL",
        "DE_STEUER_ID",
        "FR_NIR",
        "ES_DNI",
        "IT_CODICE_FISCALE",
        "NL_BSN",
        "PL_PESEL",
        "UK_NHS",
        "UK_NINO",
        "IBAN",
        "PHONE_EU",
        "SG_NRIC",
        "PHONE_SG",
    ] {
        assert!(
            prefixes.contains(&expected),
            "Expected {} to be redacted from the combined multi-locale sentence; got {:?}",
            expected,
            prefixes
        );
    }

    // R1 verification criterion: gated US_CA_DL fires only with context.
    let gated = scanner.scan("CA DL: A1234567 on file");
    assert!(gated
        .iter()
        .any(|m| m.entity_type.as_tag_prefix() == "US_CA_DL"));
    // Bare / SKU usage must never redact.
    assert!(!scanner
        .scan("Order SKU A1234567 shipped")
        .iter()
        .any(|m| m.entity_type.as_tag_prefix() == "US_CA_DL"));
}

#[test]
fn test_vault_roundtrip_and_json_key_context() {
    use pii_core::{PiiSessionVault, SecurityError, ToolTrustLevel};

    // Build the vault from the full multi-locale catalog so US_CA_DL is present.
    let catalog = PiiCatalog::with_locales(&["global", "id", "us", "eu", "sg"])
        .expect("builtin catalogs parse");
    let mut vault =
        PiiSessionVault::try_from_catalog(catalog).expect("vault builds from the combined catalog");

    // Plain-text round trip: redact then rehydrate restores the original.
    let original = "Customer NIK 3573012203950001, email user@example.com.";
    let redacted = vault.redact(original);
    assert!(!redacted.contains("3573012203950001"));
    assert!(!redacted.contains("user@example.com"));
    assert_eq!(vault.rehydrate(&redacted), original);

    // JSON object keys act as qualifying context: the leaf value alone carries
    // no prose keyword, but `driver_license` must still drive US_CA_DL. The
    // array places the value >48 bytes from the key, which raw-text scanning
    // cannot associate.
    let raw_json =
        r#"{"driver_license": ["000000000000000000000000000000000000000000000000", "A1234567"]}"#;
    let outbound = vault.redact_json(raw_json);
    assert!(
        !outbound.contains("A1234567"),
        "Outbound JSON with a `driver_license` key must be redacted, got {}",
        outbound
    );
    assert!(
        outbound.contains("driver_license"),
        "JSON keys must be preserved, got {}",
        outbound
    );

    // A *fresh* unredacted value must be redacted through the public API too,
    // and ExternalUntrusted must block it on Layer 3 (not just Layer 1).
    let mut fresh: serde_json::Value = serde_json::from_str(raw_json).expect("valid JSON");
    vault.redact_json_value(&mut fresh);
    let serialized = serde_json::to_string(&fresh).expect("serializable");
    assert!(!serialized.contains("A1234567"), "got {}", serialized);

    let mut fresh: serde_json::Value = serde_json::from_str(raw_json).expect("valid JSON");
    let blocked = vault.rehydrate_json_value(&mut fresh, ToolTrustLevel::ExternalUntrusted);
    assert!(
        matches!(blocked, Err(SecurityError::ExfiltrationBlocked { .. })),
        "ExternalUntrusted rehydration of raw JSON under a qualifying key must be blocked"
    );

    // InternalTrusted rehydration restores the original JSON value.
    let mut json: serde_json::Value =
        serde_json::from_str(&outbound).expect("round-tripped JSON is valid");
    vault
        .rehydrate_json_value(&mut json, ToolTrustLevel::InternalTrusted)
        .expect("trusted rehydration succeeds");
    let restored = serde_json::to_string(&json).expect("serializable");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&restored).expect("valid restored JSON"),
        serde_json::from_str::<serde_json::Value>(raw_json).expect("valid raw JSON")
    );
}

#[test]
fn test_rule_regex_alignment_and_prefix_overlap_resolution() {
    let catalog = PiiCatalog::with_locales(&["global", "id", "us", "eu", "sg"]).unwrap();
    let mut vault = pii_core::PiiSessionVault::from_catalog_with_key(catalog, [0x42u8; 32]);

    // PHONE_ID must not truncate a hyphenated Credit Card starting with "02 ..." or "Phone: 02-..."
    assert_eq!(
        vault.redact("Item 02 4532-0151-1283-0366"),
        "Item 02 <CREDIT_CARD_1>"
    );
    assert_eq!(
        vault.redact("Phone: 02-4532-0151-1283-0366"),
        "Phone: 02-<CREDIT_CARD_1>"
    );

    // Spaced IBAN, Amex 4-6-5, Finnish 3-digit CC phone, French multi-group phone, and SSN variants
    assert_eq!(vault.redact("DE89 3704 0044 0532 0130 00"), "<IBAN_1>");
    assert_eq!(vault.redact("3782-822463-10005"), "<CREDIT_CARD_2>");
    assert_eq!(vault.redact("+358 9 1234567"), "<PHONE_EU_1>");
    assert_eq!(vault.redact("+33 1 42 68 55 00"), "<PHONE_EU_2>");
    assert_eq!(vault.redact("123 45 6789"), "<US_SSN_1>");
    assert_eq!(vault.redact("SSN: 123456789"), "SSN: <US_SSN_2>");
}
