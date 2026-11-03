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

                // ... and MUST fire once a context keyword is present.
                let kw = rule
                    .context_keywords
                    .first()
                    .expect("require_context rules must define context keywords");
                let with_context = format!("{}: {}", kw, valid);
                let matches_ctx = scanner.scan(&with_context);
                assert!(
                    matches_ctx.iter().any(|m| m.entity_type.as_tag_prefix() == rule.tag_prefix),
                    "Expected valid sample '{}' to match context-gated rule '{}' when prefixed with '{}', got: {:?}",
                    valid,
                    rule.id,
                    kw,
                    matches_ctx
                );
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

    // One combined sentence exercising at least one entity from every locale
    // family: global, id, us, eu, sg. All built-ins must coexist without
    // false-positive tag collisions.
    let text = concat!(
        "Contact user@example.com; NIK 3573012203950001; SSN 123-45-6789; ",
        "ITIN 911-70-1234; ABA 121000248; Steuer-ID 51928327648; ",
        "NIR 195024610200145; DNI 12345678Z; Codice RSSMRA85M01H501E; ",
        "BSN 835030568; PESEL 95022812342; NHS 4139537671; NINO AA123456A; ",
        "phone +65 8123 4567."
    );
    let matches = scanner.scan(text);
    let prefixes: Vec<&str> = matches
        .iter()
        .map(|m| m.entity_type.as_tag_prefix())
        .collect();
    for expected in [
        "EMAIL",
        "ID_NIK",
        "US_SSN",
        "US_ITIN",
        "US_ROUTING_ABA",
        "DE_STEUER_ID",
        "FR_NIR",
        "ES_DNI",
        "IT_CODICE_FISCALE",
        "NL_BSN",
        "PL_PESEL",
        "UK_NHS",
        "UK_NINO",
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
