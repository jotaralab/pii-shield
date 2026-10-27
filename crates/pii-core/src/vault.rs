use crate::catalog::PiiCatalog;
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
    counters: AHashMap<EntityType, u64>,
    session_key: Zeroizing<[u8; 32]>,
    policy: SecurityPolicy,
    stateless_mode: bool,
}

impl PiiSessionVault {
    /// Creates a new session vault using OS CSPRNG for session key generation.
    pub fn new(policy: SecurityPolicy) -> Self {
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes).expect("OS CSPRNG unavailable");
        Self::with_key(policy, key_bytes)
    }

    /// Creates a vault with an explicit 32-byte key (for deterministic testing or multi-process sharing).
    pub fn with_key(policy: SecurityPolicy, key: [u8; 32]) -> Self {
        let catalog = match policy {
            SecurityPolicy::IndonesiaUuPdpStrict => {
                PiiCatalog::with_locales(&["global", "id"]).expect("Builtin catalogs valid")
            }
            SecurityPolicy::StandardGlobal => {
                PiiCatalog::with_locales(&["global", "us", "eu", "sg"]).expect("Builtin catalogs valid")
            }
        };
        let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner compilation valid");

        Self {
            scanner,
            forward_map: AHashMap::new(),
            reverse_map: AHashMap::new(),
            counters: AHashMap::new(),
            session_key: Zeroizing::new(key),
            policy,
            stateless_mode: false,
        }
    }

    /// Creates a vault from an explicit PiiCatalog and OS CSPRNG key.
    pub fn from_catalog(catalog: PiiCatalog) -> Self {
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes).expect("OS CSPRNG unavailable");
        let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner compilation valid");
        Self {
            scanner,
            forward_map: AHashMap::new(),
            reverse_map: AHashMap::new(),
            counters: AHashMap::new(),
            session_key: Zeroizing::new(key_bytes),
            policy: SecurityPolicy::IndonesiaUuPdpStrict,
            stateless_mode: false,
        }
    }

    /// Enables or disables stateless sealed-token mode.
    pub fn set_stateless_mode(&mut self, enabled: bool) {
        self.stateless_mode = enabled;
    }

    /// Derives HKDF-style subkeys from session_key: K_mac and K_enc.
    fn derive_subkeys(&self) -> ([u8; 32], [u8; 32]) {
        let mut mac = HmacSha256::new_from_slice(&*self.session_key).expect("Key valid");
        mac.update(b"pii-shield-mac");
        let k_mac = mac.finalize().into_bytes().into();

        let mut enc = HmacSha256::new_from_slice(&*self.session_key).expect("Key valid");
        enc.update(b"pii-shield-enc");
        let k_enc = enc.finalize().into_bytes().into();

        (k_mac, k_enc)
    }

    /// Domain-separated HMAC calculation without allocating intermediate strings.
    fn compute_hmac(&self, tag_prefix: &str, raw_pii: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&*self.session_key).expect("HMAC key length valid");
        mac.update(tag_prefix.as_bytes());
        mac.update(&[0u8]);
        for b in raw_pii.trim().bytes() {
            mac.update(&[b.to_ascii_lowercase()]);
        }
        mac.finalize().into_bytes().into()
    }

    /// Deterministic HMAC-SHA256-SIV sealed token creation (<PII:PREFIX:UPPER_HEX>).
    fn create_sealed_token(&self, tag_prefix: &str, raw_pii: &str) -> String {
        let (k_mac, k_enc) = self.derive_subkeys();
        let trimmed = raw_pii.trim().as_bytes();

        // 1. Compute 16-byte Synthetic IV (SIV) = HMAC(K_mac, prefix || 0x00 || plaintext)[0..16]
        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(tag_prefix.as_bytes());
        mac.update(&[0u8]);
        mac.update(trimmed);
        let siv_full = mac.finalize().into_bytes();
        let mut siv = [0u8; 16];
        siv.copy_from_slice(&siv_full[..16]);

        // 2. Counter-mode encryption with K_enc
        let mut ciphertext = Vec::with_capacity(trimmed.len());
        let mut block_idx = 0u32;
        while ciphertext.len() < trimmed.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(&siv);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks_block = ctr_mac.finalize().into_bytes();

            for &b in ks_block.iter() {
                if ciphertext.len() == trimmed.len() {
                    break;
                }
                let pt_byte = trimmed[ciphertext.len()];
                ciphertext.push(pt_byte ^ b);
            }
            block_idx += 1;
        }

        // 3. Assemble SIV || Ciphertext and encode as uppercase hex
        let mut payload = Vec::with_capacity(16 + ciphertext.len());
        payload.extend_from_slice(&siv);
        payload.extend_from_slice(&ciphertext);
        let hex_str = hex::encode_upper(payload);

        format!("<PII:{}:{}>", tag_prefix, hex_str)
    }

    /// Decrypts a stateless sealed token (<PII:PREFIX:UPPER_HEX>) into out.
    fn decrypt_sealed_token_into(&self, token: &str, out: &mut String) -> bool {
        if !token.starts_with("<PII:") || !token.ends_with('>') {
            return false;
        }
        let inner = &token[5..token.len() - 1];
        let Some(first_colon) = inner.find(':') else {
            return false;
        };
        let tag_prefix = &inner[..first_colon];
        let hex_payload = &inner[first_colon + 1..];

        let Ok(payload) = hex::decode(hex_payload) else {
            return false;
        };
        if payload.len() < 16 {
            return false;
        }

        let (k_mac, k_enc) = self.derive_subkeys();
        let (siv, ciphertext) = payload.split_at(16);

        // Decrypt ciphertext using K_enc counter-mode
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        let mut block_idx = 0u32;
        while plaintext.len() < ciphertext.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(siv);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks_block = ctr_mac.finalize().into_bytes();

            for &b in ks_block.iter() {
                if plaintext.len() == ciphertext.len() {
                    break;
                }
                let ct_byte = ciphertext[plaintext.len()];
                plaintext.push(ct_byte ^ b);
            }
            block_idx += 1;
        }

        // Verify Synthetic IV (SIV)
        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(tag_prefix.as_bytes());
        mac.update(&[0u8]);
        mac.update(&plaintext);
        let expected_siv_full = mac.finalize().into_bytes();

        if siv != &expected_siv_full[..16] {
            return false; // Authentication failed
        }

        if let Ok(pt_str) = std::str::from_utf8(&plaintext) {
            out.push_str(pt_str);
            true
        } else {
            false
        }
    }

    fn get_or_insert_token(&mut self, entity_type: EntityType, raw_pii: &str) -> String {
        let tag_prefix = entity_type.as_tag_prefix().to_string();
        if self.stateless_mode {
            return self.create_sealed_token(&tag_prefix, raw_pii);
        }

        let digest = self.compute_hmac(&tag_prefix, raw_pii);
        if let Some(existing) = self.forward_map.get(&digest) {
            return existing.clone();
        }

        let count = self.counters.entry(entity_type.clone()).or_insert(0);
        *count = count.saturating_add(1);

        let token = format!("<{}_{}>", tag_prefix, count);
        self.forward_map.insert(digest, token.clone());
        self.reverse_map
            .insert(token.clone(), Zeroizing::new(raw_pii.trim().to_string()));

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

    /// Single-pass O(M) left-to-right lexical scan rehydrating tokens without secondary injection.
    pub fn rehydrate(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'<' {
                // Potential token start
                let start = i;
                let mut end = None;
                for j in (start + 1)..bytes.len() {
                    let b = bytes[j];
                    if b == b'>' {
                        end = Some(j);
                        break;
                    }
                    if !(b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b':') {
                        break; // Not a valid token character
                    }
                }

                if let Some(end_idx) = end {
                    let candidate = &text[start..=end_idx];
                    if self.rehydrate_token_into(candidate, &mut out) {
                        i = end_idx + 1;
                        continue;
                    }
                }
            }
            // Append current char boundary
            let ch_len = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
        }

        out
    }

    /// Looks up or decrypts a single token, appending the raw value into out.
    /// Returns true if the token was recognized and rehydrated.
    pub fn rehydrate_token_into(&self, token: &str, out: &mut String) -> bool {
        if let Some(val) = self.reverse_map.get(token) {
            out.push_str(val.as_str());
            return true;
        }
        if token.starts_with("<PII:") {
            return self.decrypt_sealed_token_into(token, out);
        }
        false
    }

    /// O(1) stateful lookup for a token.
    pub fn rehydrate_token(&self, token: &str) -> Option<&str> {
        self.reverse_map.get(token).map(|z| z.as_str())
    }

    /// Recursively rehydrates all string leaves inside a serde_json::Value AST,
    /// enforcing 3-layer exfiltration defense on ExternalUntrusted tools.
    pub fn rehydrate_json_value(
        &self,
        value: &mut serde_json::Value,
        trust_level: ToolTrustLevel,
    ) -> Result<(), SecurityError> {
        match value {
            serde_json::Value::String(s) => {
                if trust_level == ToolTrustLevel::ExternalUntrusted {
                    self.check_exfiltration(s)?;
                } else {
                    // Check if string leaf itself is nested JSON
                    if (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']')) {
                        if let Ok(mut inner_val) = serde_json::from_str::<serde_json::Value>(s) {
                            self.rehydrate_json_value(&mut inner_val, trust_level)?;
                            if let Ok(serialized) = serde_json::to_string(&inner_val) {
                                *s = serialized;
                                return Ok(());
                            }
                        }
                    }
                    *s = self.rehydrate(s);
                }
            }
            serde_json::Value::Array(arr) => {
                for elem in arr {
                    self.rehydrate_json_value(elem, trust_level)?;
                }
            }
            serde_json::Value::Object(map) => {
                for (_k, v) in map {
                    self.rehydrate_json_value(v, trust_level)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Enforces 3-layer inspection on an untrusted payload string:
    /// 1. Vault tokens (<...>) or sealed tokens (<PII:...>)
    /// 2. Known session PII stored in reverse_map.values()
    /// 3. Raw PII detected by self.scanner.scan(payload)
    fn check_exfiltration(&self, payload: &str) -> Result<(), SecurityError> {
        // Layer 1: Vault tokens
        for token in self.reverse_map.keys() {
            if payload.contains(token) {
                return Err(SecurityError::ExfiltrationBlocked {
                    token: token.clone(),
                });
            }
        }
        if payload.contains("<PII:") {
            return Err(SecurityError::ExfiltrationBlocked {
                token: "<SEALED_PII>".to_string(),
            });
        }

        // Layer 2: Known session PII in reverse_map
        for (token, raw_val) in &self.reverse_map {
            let val = raw_val.as_str();
            if val.len() >= 4 && payload.contains(val) {
                return Err(SecurityError::ExfiltrationBlocked {
                    token: token.clone(),
                });
            }
        }

        // Layer 3: Scanner scan for raw PII
        let matches = self.scanner.scan(payload);
        if let Some(first_match) = matches.into_iter().next() {
            return Err(SecurityError::ExfiltrationBlocked {
                token: format!("<RAW_{}>", first_match.entity_type.as_tag_prefix()),
            });
        }

        Ok(())
    }

    /// Enforces taint-tracking ACLs before rehydrating arguments for an AI agent tool call.
    pub fn rehydrate_for_tool(
        &self,
        payload: &str,
        trust_level: ToolTrustLevel,
    ) -> Result<String, SecurityError> {
        if trust_level == ToolTrustLevel::ExternalUntrusted {
            self.check_exfiltration(payload)?;
            return Ok(payload.to_string());
        }

        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(payload) {
            self.rehydrate_json_value(&mut json_val, trust_level)?;
            serde_json::to_string(&json_val).map_err(|_| SecurityError::ExfiltrationBlocked {
                token: "<JSON_SERIALIZATION_FAILED>".to_string(),
            })
        } else {
            Ok(self.rehydrate(payload))
        }
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
        let tool_args = r#"{"nik":"<ID_NIK_1>"}"#;
        let hydrated = vault
            .rehydrate_for_tool(tool_args, ToolTrustLevel::InternalTrusted)
            .unwrap();
        assert_eq!(hydrated, r#"{"nik":"3573012203950001"}"#);

        // Untrusted external tool call is blocked from exfiltrating PII
        let untrusted = vault.rehydrate_for_tool(tool_args, ToolTrustLevel::ExternalUntrusted);
        assert!(matches!(
            untrusted,
            Err(SecurityError::ExfiltrationBlocked { .. })
        ));

        // Untrusted call with raw PII is also blocked without echoing raw PII
        let untrusted_raw = vault.rehydrate_for_tool(
            r#"{"nik":"3573012203950001"}"#,
            ToolTrustLevel::ExternalUntrusted,
        );
        assert_eq!(
            untrusted_raw,
            Err(SecurityError::ExfiltrationBlocked {
                token: "<ID_NIK_1>".to_string()
            })
        );
    }

    #[test]
    fn test_secondary_token_injection_defense() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        vault.reverse_map.insert(
            "<EMAIL_1>".to_string(),
            Zeroizing::new("user+<ID_NIK_1>@example.com".to_string()),
        );
        vault.reverse_map.insert(
            "<ID_NIK_1>".to_string(),
            Zeroizing::new("3573012203950001".to_string()),
        );

        let rehydrated = vault.rehydrate("Send to <EMAIL_1>");
        assert_eq!(rehydrated, "Send to user+<ID_NIK_1>@example.com");
    }

    #[test]
    fn test_stateless_sealed_tokens() {
        let key = [42u8; 32];
        let mut vault_a = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        vault_a.set_stateless_mode(true);

        let sealed = vault_a.redact("User NIK 3573012203950001");
        assert!(sealed.starts_with("User NIK <PII:ID_NIK:"));
        assert!(sealed.ends_with('>'));

        // Fresh vault B with key but empty reverse_map rehydrates sealed token cleanly
        let vault_b = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        let unsealed = vault_b.rehydrate(&sealed);
        assert_eq!(unsealed, "User NIK 3573012203950001");
    }
}
