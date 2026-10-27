use serde::{Deserialize, Serialize};

pub const GLOBAL_TOML: &str = include_str!("../rules/global.toml");
pub const ID_TOML: &str = include_str!("../rules/id.toml");
pub const US_TOML: &str = include_str!("../rules/us.toml");
pub const EU_TOML: &str = include_str!("../rules/eu.toml");
pub const SG_TOML: &str = include_str!("../rules/sg.toml");

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("TOML parse error: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("Rule limit exceeded: maximum {0} rules allowed")]
    RuleLimitExceeded(usize),
    #[error("Regex pattern length limit exceeded for rule {0}: maximum {1} bytes allowed")]
    PatternTooLong(String, usize),
    #[error("Unknown validator '{0}' in rule '{1}'")]
    UnknownValidator(String, String),
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
                _ => {}
            }
        }
        Ok(catalog)
    }

    /// Merges rules from a TOML string into the catalog, enforcing sanity limits.
    pub fn merge_toml_str(&mut self, toml_str: &str) -> Result<(), CatalogError> {
        let parsed: LocaleCatalog = toml::from_str(toml_str)?;
        for rule in parsed.rules {
            if self.rules.len() >= 256 {
                return Err(CatalogError::RuleLimitExceeded(256));
            }
            if rule.regex.len() > 1024 {
                return Err(CatalogError::PatternTooLong(rule.id, 1024));
            }
            if !crate::checksum::is_known_validator(&rule.validator) {
                return Err(CatalogError::UnknownValidator(rule.validator, rule.id));
            }
            // Overwrite existing rule if same ID, or append
            if let Some(pos) = self.rules.iter().position(|r| r.id == rule.id) {
                self.rules[pos] = rule;
            } else {
                self.rules.push(rule);
            }
        }
        Ok(())
    }

    /// Constructs a catalog from a single TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, CatalogError> {
        let mut catalog = Self::new();
        catalog.merge_toml_str(toml_str)?;
        Ok(catalog)
    }
}
