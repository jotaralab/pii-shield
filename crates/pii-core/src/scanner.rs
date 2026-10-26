use crate::checksum::{validate_indonesian_nik, validate_luhn};
use regex_automata::meta::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Email,
    IdNik,
    CreditCard,
    PhoneId,
}

impl EntityType {
    pub fn as_tag_prefix(&self) -> &'static str {
        match self {
            EntityType::Email => "EMAIL",
            EntityType::IdNik => "ID_NIK",
            EntityType::CreditCard => "CREDIT_CARD",
            EntityType::PhoneId => "PHONE_ID",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityMatch {
    pub entity_type: EntityType,
    pub start: usize,
    pub end: usize,
}

pub struct PiiScanner {
    multi_regex: Regex,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    pub fn new() -> Self {
        let patterns = [
            // Pattern 0: Email
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            // Pattern 1: 16-digit candidate for Indonesian NIK
            r"\d{16}",
            // Pattern 2: Credit Card candidate (13-19 digits, optional spaces/hyphens)
            r"(?:\d[ \-]*?){13,19}",
            // Pattern 3: Indonesian Phone Number (+62, 62, or 08xx)
            r"(?:\+62|62|0)8[1-9][0-9]{7,10}",
        ];

        let multi_regex = Regex::new_many(&patterns).expect("Failed to compile DFA patterns");
        Self { multi_regex }
    }

    /// Scans input text in a single pass and filters candidates via algorithmic checksums.
    pub fn scan(&self, text: &str) -> Vec<EntityMatch> {
        let mut results = Vec::new();

        for mat in self.multi_regex.find_iter(text) {
            let slice = &text[mat.start()..mat.end()];
            let entity_type = match mat.pattern().as_usize() {
                0 => Some(EntityType::Email),
                1 => {
                    if validate_indonesian_nik(slice) {
                        Some(EntityType::IdNik)
                    } else if validate_luhn(slice) {
                        Some(EntityType::CreditCard)
                    } else {
                        None
                    }
                }
                2 => {
                    if validate_luhn(slice) {
                        Some(EntityType::CreditCard)
                    } else {
                        None
                    }
                }
                3 => Some(EntityType::PhoneId),
                _ => None,
            };

            if let Some(et) = entity_type {
                results.push(EntityMatch {
                    entity_type: et,
                    start: mat.start(),
                    end: mat.end(),
                });
            }
        }

        results
    }
}
