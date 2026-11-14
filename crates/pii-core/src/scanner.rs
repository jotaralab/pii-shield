use crate::catalog::PiiCatalog;
use crate::checksum::validate_by_name;
use regex_automata::meta::{Config, Regex};
use regex_automata::{Anchored, Input};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Email,
    IdNik,
    IdNpwp,
    CreditCard,
    PhoneId,
    UsSsn,
    Iban,
    SgNric,
    PhoneUs,
    PhoneEu,
    PhoneSg,
    Custom(String),
}

impl EntityType {
    pub fn as_tag_prefix(&self) -> &str {
        match self {
            EntityType::Email => "EMAIL",
            EntityType::IdNik => "ID_NIK",
            EntityType::IdNpwp => "ID_NPWP",
            EntityType::CreditCard => "CREDIT_CARD",
            EntityType::PhoneId => "PHONE_ID",
            EntityType::UsSsn => "US_SSN",
            EntityType::Iban => "IBAN",
            EntityType::SgNric => "SG_NRIC",
            EntityType::PhoneUs => "PHONE_US",
            EntityType::PhoneEu => "PHONE_EU",
            EntityType::PhoneSg => "PHONE_SG",
            EntityType::Custom(s) => s.as_str(),
        }
    }

    pub fn from_tag_prefix(prefix: &str) -> Self {
        match prefix {
            "EMAIL" => EntityType::Email,
            "ID_NIK" => EntityType::IdNik,
            "ID_NPWP" => EntityType::IdNpwp,
            "CREDIT_CARD" => EntityType::CreditCard,
            "PHONE_ID" => EntityType::PhoneId,
            "US_SSN" => EntityType::UsSsn,
            "IBAN" => EntityType::Iban,
            "SG_NRIC" => EntityType::SgNric,
            "PHONE_US" => EntityType::PhoneUs,
            "PHONE_EU" => EntityType::PhoneEu,
            "PHONE_SG" => EntityType::PhoneSg,
            other => EntityType::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityMatch {
    pub entity_type: EntityType,
    pub start: usize,
    pub end: usize,
}

struct CompiledRule {
    entity_type: EntityType,
    validator: String,
    priority: u16,
    context_keywords: Vec<String>,
    require_context: bool,
    regex: Regex,
}

/// Case-insensitive keyword hit with ASCII word boundaries: the bytes
/// immediately before and after a hit must not be alphanumeric. This stops
/// short keywords like `dl` or `cf` from matching inside `"bundle"`.
///
/// Boundary checks run against the FULL `haystack`, while candidate starts are
/// restricted to `[start, end)`. Slicing the window first would turn the
/// ±48-byte cutoff into a synthetic word boundary (e.g. `"soap.wsdl"` sliced
/// right before `"dl"`).
#[inline]
fn contains_keyword_in(haystack: &[u8], start: usize, end: usize, needle: &[u8]) -> bool {
    if needle.is_empty() || start >= end || end > haystack.len() || needle.len() > end - start {
        return false;
    }
    for i in start..=(end - needle.len()) {
        let hit_end = i + needle.len();
        let prev_ok = i == 0 || !haystack[i - 1].is_ascii_alphanumeric();
        if !prev_ok {
            continue;
        }
        let next_ok = hit_end == haystack.len() || !haystack[hit_end].is_ascii_alphanumeric();
        if next_ok
            && haystack[i..hit_end]
                .iter()
                .zip(needle.iter())
                .all(|(&h, &n)| h.eq_ignore_ascii_case(&n))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[inline]
fn contains_keyword(haystack: &[u8], needle: &[u8]) -> bool {
    contains_keyword_in(haystack, 0, haystack.len(), needle)
}

/// Identifier-boundary-aware case-insensitive hit for machine key context
/// (JSON/MCP object keys like `"driver_license"`, `"driverLicense"`). A hit
/// must be delimited by the key start/end, a non-alphanumeric separator
/// (`_`, `-`, `.`, ` `), or a camelCase / letter-digit transition. Plain
/// subword hits such as `"dl"` inside `"bundle"` or `"buildLog"` are rejected.
#[inline]
fn contains_key_fragment(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    for start in 0..=(haystack.len() - needle.len()) {
        let end = start + needle.len();
        if !haystack[start..end]
            .iter()
            .zip(needle.iter())
            .all(|(&h, &n)| h.eq_ignore_ascii_case(&n))
        {
            continue;
        }
        let prev_ok = if start == 0 {
            true
        } else {
            is_identifier_boundary(haystack[start - 1], haystack[start])
        };
        let next_ok = if end == haystack.len() {
            true
        } else {
            is_identifier_boundary(haystack[end - 1], haystack[end])
        };
        if prev_ok && next_ok {
            return true;
        }
    }
    false
}

/// True when two adjacent identifier bytes mark a word boundary, either
/// because of a non-alphanumeric separator, a lowercase→uppercase camelCase
/// transition, or a letter↔digit transition.
#[inline]
fn is_identifier_boundary(prev: u8, curr: u8) -> bool {
    !prev.is_ascii_alphanumeric()
        || (prev.is_ascii_lowercase() && curr.is_ascii_uppercase())
        || (prev.is_ascii_alphabetic() != curr.is_ascii_alphabetic())
}

pub struct PiiScanner {
    multi_regex: Regex,
    rules: Vec<CompiledRule>,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    /// Creates a scanner with default global and Indonesian rules.
    pub fn new() -> Self {
        let catalog =
            PiiCatalog::with_locales(&["global", "id"]).expect("Failed to load default catalogs");
        Self::from_catalog(&catalog).expect("Failed to compile default rules")
    }

    /// Compiles a scanner from a declarative PiiCatalog.
    pub fn from_catalog(catalog: &PiiCatalog) -> Result<Self, String> {
        let mut patterns = Vec::new();
        let mut compiled_rules = Vec::new();

        let meta_config = Config::new()
            .nfa_size_limit(Some(10 * 1024 * 1024))
            .dfa_size_limit(Some(2 * 1024 * 1024));

        for rule in &catalog.rules {
            // Struct-literal catalogs bypass `merge_toml_str`, so re-validate
            // the require_context invariant here: a gated rule with no usable
            // keyword would silently reject every candidate forever.
            if rule.require_context
                && (rule.context_keywords.is_empty()
                    || rule.context_keywords.iter().any(|kw| kw.trim().is_empty()))
            {
                return Err(format!(
                    "Rule '{}' sets require_context = true but defines no usable context_keywords",
                    rule.id
                ));
            }
            patterns.push(rule.regex.as_str());
            let rule_regex = Regex::builder()
                .configure(meta_config.clone())
                .build(&rule.regex)
                .map_err(|e| format!("Invalid regex for rule {}: {:?}", rule.id, e))?;

            compiled_rules.push(CompiledRule {
                entity_type: EntityType::from_tag_prefix(&rule.tag_prefix),
                validator: rule.validator.clone(),
                priority: rule.priority,
                context_keywords: rule.context_keywords.clone(),
                require_context: rule.require_context,
                regex: rule_regex,
            });
        }

        let multi_regex = Regex::builder()
            .configure(meta_config)
            .build_many(&patterns)
            .map_err(|e| format!("Failed to build multi-pattern regex: {}", e))?;

        Ok(Self {
            multi_regex,
            rules: compiled_rules,
        })
    }

    /// Scans text using the 3-Stage Cascading Sieve with UTF-8 safe context scoring
    /// and multi-rule candidate evaluation at overlapping spans.
    pub fn scan(&self, text: &str) -> Vec<EntityMatch> {
        self.scan_with_context(text, None)
    }

    /// Like [`PiiScanner::scan`], but additionally treats `key_context`
    /// (e.g. a JSON / MCP object key such as `"driver_license"`) as standing
    /// context for rules that declare `context_keywords` / `require_context`.
    /// `key_context` participates in both the `require_context` hard gate and
    /// the `+25` keyword bonus (without the ±25 window scan of free text).
    pub fn scan_with_context(&self, text: &str, key_context: Option<&str>) -> Vec<EntityMatch> {
        let mut results = Vec::new();
        let mut pos = 0;
        let text_bytes = text.as_bytes();

        while pos < text.len() {
            let input = Input::new(text).span(pos..text.len());
            let Some(mat) = self.multi_regex.find(input) else {
                break;
            };

            let match_start = mat.start();

            let best_match = self.best_match_at(text, text_bytes, match_start, key_context);

            if let Some((winning, winning_score, winning_priority)) = best_match {
                // Lookahead overlap resolution: if a higher-priority, higher-scoring
                // rule starts inside `(match_start + 1)..winning.end` (e.g. a
                // Credit Card or SSN starting after a false prefix match), advance
                // to that interior start instead of truncating the higher-priority entity.
                let mut inner_override: Option<usize> = None;
                let mut probe_pos = match_start + 1;
                while probe_pos < winning.end {
                    while probe_pos < winning.end && !text.is_char_boundary(probe_pos) {
                        probe_pos += 1;
                    }
                    if probe_pos >= winning.end {
                        break;
                    }
                    let probe_input = Input::new(text).span(probe_pos..text.len());
                    let Some(probe_mat) = self.multi_regex.find(probe_input) else {
                        break;
                    };
                    if probe_mat.start() >= winning.end {
                        break;
                    }
                    if let Some((_, inner_score, inner_priority)) =
                        self.best_match_at(text, text_bytes, probe_mat.start(), key_context)
                    {
                        if inner_priority > winning_priority && inner_score > winning_score {
                            inner_override = Some(probe_mat.start());
                            break;
                        }
                    }
                    probe_pos = probe_mat.start() + 1;
                }

                if let Some(next_start) = inner_override {
                    pos = next_start;
                } else {
                    pos = winning.end;
                    results.push(winning);
                }
            } else {
                // If no rule passed checksum at match_start, advance cursor to next char boundary
                let mut next_pos = match_start + 1;
                while next_pos < text.len() && !text.is_char_boundary(next_pos) {
                    next_pos += 1;
                }
                pos = next_pos;
            }
        }

        results
    }

    /// Evaluates all compiled rules anchored at `match_start` and returns the
    /// highest-scoring valid match `(EntityMatch, score, priority)`, if any.
    fn best_match_at(
        &self,
        text: &str,
        text_bytes: &[u8],
        match_start: usize,
        key_context: Option<&str>,
    ) -> Option<(EntityMatch, i32, i32)> {
        let mut best_match: Option<(EntityMatch, i32, i32)> = None;

        for rule in &self.rules {
            let anchored_input = Input::new(text)
                .span(match_start..text.len())
                .anchored(Anchored::Yes);

            if let Some(r_mat) = rule.regex.find(anchored_input) {
                let slice = &text[r_mat.start()..r_mat.end()];

                // Do not allow PHONE_ID to match a prefix immediately followed by `-[0-9]`.
                if rule.entity_type.as_tag_prefix() == "PHONE_ID"
                    && r_mat.end() + 1 < text_bytes.len()
                    && text_bytes[r_mat.end()] == b'-'
                    && text_bytes[r_mat.end() + 1].is_ascii_digit()
                {
                    continue;
                }

                // Stage 3 Checksum Verification
                if validate_by_name(&rule.validator, slice) {
                    let win_start = match_start.saturating_sub(48);
                    let win_end = (r_mat.end() + 48).min(text_bytes.len());

                    let keyword_hit = key_context.is_some_and(|key| {
                        rule.context_keywords
                            .iter()
                            .any(|kw| contains_key_fragment(key.as_bytes(), kw.as_bytes()))
                    }) || {
                        let left_hit = rule.context_keywords.iter().any(|kw| {
                            contains_keyword_in(text_bytes, win_start, match_start, kw.as_bytes())
                        });
                        left_hit
                            || rule.context_keywords.iter().any(|kw| {
                                contains_keyword_in(text_bytes, r_mat.end(), win_end, kw.as_bytes())
                            })
                    };

                    if rule.require_context && !keyword_hit {
                        continue;
                    }

                    // Contiguous 9-digit US_SSN (without dashes/spaces) has no mathematical
                    // check digit, so require a context keyword when no separators are present.
                    if rule.entity_type.as_tag_prefix() == "US_SSN"
                        && (r_mat.end() - r_mat.start()) == 9
                        && !keyword_hit
                    {
                        continue;
                    }

                    let priority = rule.priority as i32;
                    let mut score = priority;
                    if keyword_hit && !rule.require_context {
                        score += 25;
                    }

                    let span_len = (r_mat.end() - r_mat.start()) as i32;
                    score += span_len * 2;

                    let em = EntityMatch {
                        entity_type: rule.entity_type.clone(),
                        start: r_mat.start(),
                        end: r_mat.end(),
                    };

                    if let Some((ref best_em, best_score, _)) = best_match {
                        let best_len = (best_em.end - best_em.start) as i32;
                        if score > best_score || (score == best_score && span_len > best_len) {
                            best_match = Some((em, score, priority));
                        }
                    } else {
                        best_match = Some((em, score, priority));
                    }
                }
            }
        }

        best_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multi_locale_scanner() -> PiiScanner {
        let catalog = crate::catalog::PiiCatalog::with_locales(&["global", "id", "us", "eu", "sg"])
            .expect("builtin catalogs parse");
        PiiScanner::from_catalog(&catalog).expect("scanner compiles")
    }

    #[test]
    fn test_contains_keyword_word_bounds() {
        assert!(contains_keyword(b"handle this", b"handle"));
        assert!(!contains_keyword(b"bundle SKU", b"dl"));
        assert!(!contains_keyword(b"kindly process", b"dl"));
        assert!(contains_keyword(b"via dl verification", b"dl"));
        assert!(contains_keyword(b"CA-DMV record", b"dmv"));
        // keyword never matches inside a digit-run/identifier
        assert!(!contains_keyword(b"A1234567", b"123"));
    }

    #[test]
    fn test_contains_keyword_in_respects_full_text_boundaries() {
        // Left cutoff landing mid-word: the window starts at "dl" of "wsdl",
        // but the preceding byte in the full text is the alphanumeric 's'.
        assert!(!contains_keyword_in(b"wsdlA1234567", 2, 6, b"dl"));
        // Right cutoff landing mid-word: the window ends after "dl" of
        // "adlz", but the following byte in the full text is alphanumeric.
        assert!(!contains_keyword_in(b"A1234567 dlz", 9, 11, b"dl"));
        // A genuine standalone keyword inside the window is still found.
        assert!(contains_keyword_in(b" dl A1234567", 1, 4, b"dl"));
        assert!(contains_keyword_in(b"A1234567 dl z", 9, 11, b"dl"));
    }

    #[test]
    fn test_contains_key_fragment_identifier_boundaries() {
        for key in [
            "bundle",
            "bundle_id",
            "handler",
            "deadline",
            "idle",
            "middle",
            "deadlock",
            "childList",
            "readLine",
            "cardLimit",
            "uploadLink",
            "buildLog",
            "recordLocator",
        ] {
            assert!(
                !contains_key_fragment(key.as_bytes(), b"dl"),
                "key {:?} must not satisfy the `dl` keyword",
                key
            );
        }
        for key in ["dl", "ca_dl", "camelDl", "dl_number", "someDl"] {
            assert!(
                contains_key_fragment(key.as_bytes(), b"dl"),
                "key {:?} must satisfy the `dl` keyword",
                key
            );
        }
    }

    #[test]
    fn test_json_key_context_does_not_redact_skus() {
        let scanner = multi_locale_scanner();
        for key in ["bundle", "handler", "buildLog", "deadline"] {
            assert!(
                !scanner
                    .scan_with_context("A1234567", Some(key))
                    .iter()
                    .any(|m| m.entity_type.as_tag_prefix() == "US_CA_DL"),
                "key {:?} must not gate US_CA_DL",
                key
            );
        }
        for key in ["driver_license", "driverLicense", "ca_dl"] {
            assert!(
                scanner
                    .scan_with_context("A1234567", Some(key))
                    .iter()
                    .any(|m| m.entity_type.as_tag_prefix() == "US_CA_DL"),
                "key {:?} must gate US_CA_DL",
                key
            );
        }
    }

    #[test]
    fn test_context_window_cutoffs_are_not_word_boundaries() {
        let scanner = multi_locale_scanner();
        for text in [
            "soap.wsdl returned ok status for order packet item SKU A1234567",
            "Order SKU A1234567 was processed normally by system module kernel32.dll",
        ] {
            assert!(
                !scanner
                    .scan(text)
                    .iter()
                    .any(|m| m.entity_type.as_tag_prefix() == "US_CA_DL"),
                "window cutoff must not synthesize a `dl` keyword in {:?}",
                text
            );
        }
    }

    #[test]
    fn test_longer_valid_span_outranks_short_prefix() {
        let scanner = multi_locale_scanner();
        // A 12-byte phone must not be truncated to the 9-byte ABA prefix.
        for text in ["021555123-45", "081234562 789"] {
            let matches = scanner.scan(text);
            assert_eq!(matches.len(), 1, "expected one match for {:?}", text);
            assert_eq!(
                matches[0].entity_type.as_tag_prefix(),
                "PHONE_ID",
                "PHONE_ID must win for {:?}",
                text
            );
            assert_eq!((matches[0].start, matches[0].end), (0, text.len()));
        }

        // A banking keyword must not let an ABA prefix truncate an email.
        let email = "Send bank receipt to 121000248@example.com";
        let matches = scanner.scan(email);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].entity_type.as_tag_prefix(), "EMAIL");
        assert_eq!(
            &email[matches[0].start..matches[0].end],
            "121000248@example.com"
        );

        // A checksum-less NIE must not be truncated by gated US_CA_DL.
        for text in [
            "ID card: Y2345678-Z",
            "ID card: Y2345678 Z",
            "ID card: Y2345678Z",
        ] {
            let matches = scanner.scan(text);
            assert_eq!(
                matches.len(),
                1,
                "expected one ES_DNI match for {:?}, got {:?}",
                text,
                matches
            );
            assert_eq!(matches[0].entity_type.as_tag_prefix(), "ES_DNI");
            assert_eq!(matches[0].start, 9, "match must start at the NIE body");
            assert_eq!(matches[0].end, text.len(), "NIE must not be truncated");
        }

        // Spaced German Steuer-IDs must beat a 9-digit BSN/ABA prefix.
        let de = "51 928327648";
        let matches = scanner.scan(de);
        assert_eq!(matches.len(), 1, "expected one match for {:?}", de);
        assert_eq!(matches[0].entity_type.as_tag_prefix(), "DE_STEUER_ID");
        assert_eq!((matches[0].start, matches[0].end), (0, de.len()));
    }
}
