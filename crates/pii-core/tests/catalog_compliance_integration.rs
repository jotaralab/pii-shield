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
