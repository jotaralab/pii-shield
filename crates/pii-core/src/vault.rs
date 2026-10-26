use crate::scanner::{EntityType, PiiScanner};
use ahash::AHashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPolicy {
    IndonesiaUuPdpStrict,
    StandardGlobal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTrustLevel {
    /// Internal VPC databases, ERPs, or trusted microservices (allowed to rehydrate PII).
    InternalTrusted,
    /// External third-party APIs, web search, or untrusted MCP servers (blocked from rehydrating PII).
    ExternalUntrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    ExfiltrationBlocked { token: String },
}

/// Session-scoped bi-directional pseudonymization vault.
/// Ensures consistent entity tokens across multi-turn agent loops while wiping raw PII on Drop.
pub struct PiiSessionVault {
    scanner: PiiScanner,
    forward_map: AHashMap<[u8; 32], String>,
    reverse_map: AHashMap<String, Zeroizing<String>>,
    counters: AHashMap<EntityType, u32>,
    session_key: Zeroizing<[u8; 32]>,
    _policy: SecurityPolicy,
}

impl PiiSessionVault {
    pub fn new(policy: SecurityPolicy) -> Self {
        // Deterministic per-session ephemeral key (replace with OS CSPRNG in production)
        let session_key = Zeroizing::new(*b"jotaralab-ephemeral-session-key!");
        Self {
            scanner: PiiScanner::new(),
            forward_map: AHashMap::new(),
            reverse_map: AHashMap::new(),
            counters: AHashMap::new(),
            session_key,
            _policy: policy,
        }
    }

    fn compute_hmac(&self, raw_pii: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&*self.session_key).expect("HMAC key length valid");
        mac.update(raw_pii.trim().to_lowercase().as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn get_or_insert_token(&mut self, entity_type: EntityType, raw_pii: &str) -> String {
        let digest = self.compute_hmac(raw_pii);
        if let Some(existing) = self.forward_map.get(&digest) {
            return existing.clone();
        }

        let count = self.counters.entry(entity_type).or_insert(0);
        *count += 1;

        let token = format!("<{}_{}>", entity_type.as_tag_prefix(), count);
        self.forward_map.insert(digest, token.clone());
        self.reverse_map
            .insert(token.clone(), Zeroizing::new(raw_pii.to_string()));

        token
    }

    /// Scrubs raw text and replaces detected PII with typed session-consistent tokens.
    pub fn redact(&mut self, input: &str) -> String {
        let matches = self.scanner.scan(input);
        if matches.is_empty() {
            return input.to_string();
        }

        let mut out = String::with_capacity(input.len());
        let mut last_idx = 0;

        for m in matches {
            if m.start < last_idx {
                continue;
            }
            out.push_str(&input[last_idx..m.start]);
            let raw_slice = &input[m.start..m.end];
            let token = self.get_or_insert_token(m.entity_type, raw_slice);
            out.push_str(&token);
            last_idx = m.end;
        }
        out.push_str(&input[last_idx..]);
        out
    }

    /// Rehydrates tokenized text back to original values for authorized responses.
    pub fn rehydrate(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (token, raw_val) in &self.reverse_map {
            if result.contains(token) {
                result = result.replace(token, raw_val.as_str());
            }
        }
        result
    }

    /// Enforces taint-tracking ACLs before rehydrating arguments for an AI agent tool call.
    pub fn rehydrate_for_tool(
        &self,
        payload: &str,
        trust_level: ToolTrustLevel,
    ) -> Result<String, SecurityError> {
        for (token, _) in &self.reverse_map {
            if payload.contains(token) && trust_level == ToolTrustLevel::ExternalUntrusted {
                return Err(SecurityError::ExfiltrationBlocked {
                    token: token.clone(),
                });
            }
        }
        Ok(self.rehydrate(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_roundtrip_and_exfiltration_guard() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);

        let prompt = "Cek status NIK 3573012203950001 dan email fitra@jotaralab.com";
        let scrubbed = vault.redact(prompt);
        assert_eq!(scrubbed, "Cek status NIK <ID_NIK_1> dan email <EMAIL_1>");

        // Entity continuity check: same NIK maps to <ID_NIK_1>
        let db_row = "Record: 3573012203950001 | HP: 081234567890";
        let scrubbed_row = vault.redact(db_row);
        assert_eq!(scrubbed_row, "Record: <ID_NIK_1> | HP: <PHONE_ID_1>");

        // Trusted tool call succeeds
        let tool_args = r#"{"nik": "<ID_NIK_1>"}"#;
        let hydrated = vault
            .rehydrate_for_tool(tool_args, ToolTrustLevel::InternalTrusted)
            .unwrap();
        assert_eq!(hydrated, r#"{"nik": "3573012203950001"}"#);

        // Untrusted external tool call is blocked from exfiltrating PII
        let untrusted = vault.rehydrate_for_tool(tool_args, ToolTrustLevel::ExternalUntrusted);
        assert!(matches!(
            untrusted,
            Err(SecurityError::ExfiltrationBlocked { .. })
        ));
    }
}
