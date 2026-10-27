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
    regex: Regex,
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
        let catalog = PiiCatalog::with_locales(&["global", "id"]).expect("Failed to load default catalogs");
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
            patterns.push(rule.regex.as_str());
            let rule_regex = Regex::builder()
                .configure(meta_config.clone())
                .build(&rule.regex)
                .map_err(|e| format!("Invalid regex for rule {}: {}", rule.id, e))?;

            compiled_rules.push(CompiledRule {
                entity_type: EntityType::from_tag_prefix(&rule.tag_prefix),
                validator: rule.validator.clone(),
                priority: rule.priority,
                context_keywords: rule.context_keywords.clone(),
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
        let mut results = Vec::new();
        let mut pos = 0;
        let text_bytes = text.as_bytes();

        while pos < text.len() {
            let input = Input::new(text).span(pos..text.len());
            let Some(mat) = self.multi_regex.find(input) else {
                break;
            };

            let match_start = mat.start();

            // Evaluate all compiled rules matching at this start position
            let mut best_match: Option<(EntityMatch, i32)> = None;

            for rule in &self.rules {
                let anchored_input = Input::new(text)
                    .span(match_start..text.len())
                    .anchored(Anchored::Yes);

                if let Some(r_mat) = rule.regex.find(anchored_input) {
                    let slice = &text[r_mat.start()..r_mat.end()];

                    // Stage 3 Checksum Verification
                    if validate_by_name(&rule.validator, slice) {
                        // Stage 2: Context Keyword & Priority Scoring
                        let mut score = rule.priority as i32;

                        // Check ±48 bytes window safely on bytes for ASCII context keywords
                        let win_start = match_start.saturating_sub(48);
                        let win_end = (r_mat.end() + 48).min(text_bytes.len());
                        let context_slice = &text_bytes[win_start..win_end];

                        for kw in &rule.context_keywords {
                            if contains_ignore_ascii_case(context_slice, kw.as_bytes()) {
                                score += 25;
                                break;
                            }
                        }

                        // Specificity bonus: longer span preferred as tiebreaker
                        score += (r_mat.end() - r_mat.start()) as i32;

                        let em = EntityMatch {
                            entity_type: rule.entity_type.clone(),
                            start: r_mat.start(),
                            end: r_mat.end(),
                        };

                        if let Some((_, best_score)) = best_match {
                            if score > best_score {
                                best_match = Some((em, score));
                            }
                        } else {
                            best_match = Some((em, score));
                        }
                    }
                }
            }

            if let Some((winning, _)) = best_match {
                pos = winning.end;
                results.push(winning);
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
}

#[inline]
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window.iter().zip(needle.iter()).all(|(&h, &n)| h.to_ascii_lowercase() == n.to_ascii_lowercase())
    })
}
