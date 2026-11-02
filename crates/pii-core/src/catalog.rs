use serde::{Deserialize, Serialize};
use std::fmt;

pub const GLOBAL_TOML: &str = include_str!("../rules/global.toml");
pub const ID_TOML: &str = include_str!("../rules/id.toml");
pub const US_TOML: &str = include_str!("../rules/us.toml");
pub const EU_TOML: &str = include_str!("../rules/eu.toml");
pub const SG_TOML: &str = include_str!("../rules/sg.toml");

#[derive(Debug)]
pub enum CatalogError {
    ParseError(toml::de::Error),
    RuleLimitExceeded(usize),
    PatternTooLong(String, usize),
    UnknownValidator(String, String),
    UnknownLocale(String),
    InvalidTagPrefix(String),
    InvalidRegex(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::ParseError(e) => write!(f, "TOML parse error: {}", e),
            CatalogError::RuleLimitExceeded(max) => {
                write!(f, "Rule limit exceeded: maximum {} rules allowed", max)
            }
            CatalogError::PatternTooLong(id, max) => write!(
                f,
                "Regex pattern length limit exceeded for rule {}: maximum {} bytes allowed",
                id, max
            ),
            CatalogError::UnknownValidator(val, id) => {
                write!(f, "Unknown validator '{}' in rule '{}'", val, id)
            }
            CatalogError::UnknownLocale(loc) => write!(
                f,
                "Unknown locale '{}': expected one of global, id, us, eu, sg",
                loc
            ),
            CatalogError::InvalidTagPrefix(prefix) => write!(
                f,
                "Invalid tag_prefix '{}': must be non-empty and contain only ASCII uppercase letters, digits, and underscores",
                prefix
            ),
            CatalogError::InvalidRegex(err) => {
                write!(f, "PII catalog rule regex invalid: {}", err)
            }
        }
    }
}

impl std::error::Error for CatalogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CatalogError::ParseError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<toml::de::Error> for CatalogError {
    fn from(err: toml::de::Error) -> Self {
        CatalogError::ParseError(err)
    }
}

/// A declarative PII rule specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiiRuleSpec {
    pub id: String,
    pub tag_prefix: String,
    #[serde(default)]
    pub description: String,
    pub regex: String,
    #[serde(default = "default_validator")]
    pub validator: String,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default)]
    pub context_keywords: Vec<String>,
    #[serde(default)]
    pub valid_samples: Vec<String>,
    #[serde(default)]
    pub invalid_samples: Vec<String>,
}

fn default_validator() -> String {
    "none".to_string()
}

fn default_priority() -> u16 {
    50
}

/// A locale catalog containing multiple PII rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocaleCatalog {
    pub locale: String,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<PiiRuleSpec>,
}

/// The aggregated PII catalog compiled from multiple locales or custom TOML sources.
#[derive(Debug, Clone, Default)]
pub struct PiiCatalog {
    pub rules: Vec<PiiRuleSpec>,
}

impl PiiCatalog {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Loads built-in catalogs for the specified locales (e.g. &["global", "id"]).
    pub fn with_locales(locales: &[&str]) -> Result<Self, CatalogError> {
        let mut catalog = Self::new();
        for &loc in locales {
            match loc {
                "global" => catalog.merge_toml_str(GLOBAL_TOML)?,
                "id" => catalog.merge_toml_str(ID_TOML)?,
                "us" => catalog.merge_toml_str(US_TOML)?,
                "eu" => catalog.merge_toml_str(EU_TOML)?,
                "sg" => catalog.merge_toml_str(SG_TOML)?,
                other => return Err(CatalogError::UnknownLocale(other.to_string())),
            }
        }
        Ok(catalog)
    }

    /// Merges rules from a TOML string into the catalog, enforcing sanity limits.
    /// Atomic: on any validation error the catalog is left untouched.
    pub fn merge_toml_str(&mut self, toml_str: &str) -> Result<(), CatalogError> {
        let parsed: LocaleCatalog = toml::from_str(toml_str)?;

        // Phase 1: validate every incoming spec before mutating anything.
        for rule in &parsed.rules {
            if rule.regex.len() > 1024 {
                return Err(CatalogError::PatternTooLong(rule.id.clone(), 1024));
            }
            if !crate::checksum::is_known_validator(&rule.validator) {
                return Err(CatalogError::UnknownValidator(
                    rule.validator.clone(),
                    rule.id.clone(),
                ));
            }
            if rule.tag_prefix.is_empty()
                || !rule
                    .tag_prefix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(CatalogError::InvalidTagPrefix(rule.tag_prefix.clone()));
            }
        }

        // Phase 2: stage the merged rule set directly. Existing IDs (both
        // built-in and intra-TOML duplicates) are overridden in place by an
        // earlier position match, so the *last* definition of an ID wins. The
        // 256-rule cap only applies to genuinely new IDs.
        let mut staged = self.rules.clone();
        for rule in parsed.rules {
            if let Some(pos) = staged.iter().position(|r| r.id == rule.id) {
                staged[pos] = rule;
            } else {
                if staged.len() >= 256 {
                    return Err(CatalogError::RuleLimitExceeded(256));
                }
                staged.push(rule);
            }
        }

        // Phase 3: fail fast on regexes the combined catalog cannot compile
        // (also enforces combined multi-pattern NFA/DFA size limits). The
        // error string already identifies the offending rule id.
        let staged_catalog = PiiCatalog {
            rules: staged.clone(),
        };
        if let Err(err) = crate::scanner::PiiScanner::from_catalog(&staged_catalog) {
            return Err(CatalogError::InvalidRegex(err));
        }

        // Phase 4: atomic commit.
        self.rules = staged;
        Ok(())
    }

    /// Constructs a catalog from a single TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, CatalogError> {
        let mut catalog = Self::new();
        catalog.merge_toml_str(toml_str)?;
        Ok(catalog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_locales_rejects_unknown_locale() {
        assert!(matches!(
            PiiCatalog::with_locales(&["global_typo"]),
            Err(CatalogError::UnknownLocale(_))
        ));
        assert!(PiiCatalog::with_locales(&["global", "id"]).is_ok());
    }

    #[test]
    fn test_merge_rejects_bad_tag_prefix() {
        let mut catalog = PiiCatalog::new();
        let err = catalog.merge_toml_str(
            r#"
locale = "x"
name = "X"

[[rules]]
id = "X1"
tag_prefix = "br_cpf"
regex = "\\d+"
"#,
        );
        assert!(matches!(err, Err(CatalogError::InvalidTagPrefix(_))));

        let mut catalog = PiiCatalog::new();
        let err = catalog.merge_toml_str(
            r#"
locale = "x"
name = "X"

[[rules]]
id = "X1"
tag_prefix = ""
regex = "\\d+"
"#,
        );
        assert!(matches!(err, Err(CatalogError::InvalidTagPrefix(_))));
    }

    #[test]
    fn test_merge_rejects_invalid_regex() {
        let mut catalog = PiiCatalog::new();
        let err = catalog.merge_toml_str(
            r#"
locale = "x"
name = "X"

[[rules]]
id = "BAD"
tag_prefix = "BAD"
regex = '(unbalanced['
"#,
        );
        assert!(matches!(err, Err(CatalogError::InvalidRegex(ref msg)) if msg.contains("BAD")));
    }
}
