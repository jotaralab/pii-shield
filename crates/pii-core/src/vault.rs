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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFormat {
    Sequential,
    CompactHash,
    StatelessSealed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    ExfiltrationBlocked { token: String },
    InvalidStateBlob,
    StateConflict { token: String },
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::ExfiltrationBlocked { token } => {
                write!(f, "PII exfiltration blocked: {}", token)
            }
            SecurityError::InvalidStateBlob => write!(f, "Invalid or corrupted state blob"),
            SecurityError::StateConflict { token } => {
                write!(f, "State conflict on token: {}", token)
            }
        }
    }
}

impl std::error::Error for SecurityError {}

const BASE36_CHARS: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn encode_base36(mut val: u64, min_len: usize) -> String {
    let mut buf = Vec::with_capacity(min_len.max(1));
    while val > 0 {
        buf.push(BASE36_CHARS[(val % 36) as usize]);
        val /= 36;
    }
    while buf.len() < min_len {
        buf.push(b'0');
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_default()
}

#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Session-scoped bi-directional pseudonymization vault.
/// Ensures consistent entity tokens across multi-turn agent loops while wiping raw PII on Drop.
pub struct PiiSessionVault {
    scanner: PiiScanner,
    forward_map: AHashMap<[u8; 32], String>,
    reverse_map: AHashMap<String, (EntityType, Zeroizing<String>)>,
    counters: AHashMap<EntityType, u64>,
    dirty_tokens: Vec<String>,
    session_key: Zeroizing<[u8; 32]>,
    policy: SecurityPolicy,
    token_format: TokenFormat,
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
                PiiCatalog::with_locales(&["global", "us", "eu", "sg"])
                    .expect("Builtin catalogs valid")
            }
        };
        let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner compilation valid");

        Self {
            scanner,
            forward_map: AHashMap::new(),
            reverse_map: AHashMap::new(),
            counters: AHashMap::new(),
            dirty_tokens: Vec::new(),
            session_key: Zeroizing::new(key),
            policy,
            token_format: TokenFormat::Sequential,
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
            dirty_tokens: Vec::new(),
            session_key: Zeroizing::new(key_bytes),
            policy: SecurityPolicy::IndonesiaUuPdpStrict,
            token_format: TokenFormat::Sequential,
        }
    }

    /// Creates a vault from an explicit PiiCatalog and explicit 32-byte key.
    pub fn from_catalog_with_key(catalog: PiiCatalog, key: [u8; 32]) -> Self {
        let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner compilation valid");
        Self {
            scanner,
            forward_map: AHashMap::new(),
            reverse_map: AHashMap::new(),
            counters: AHashMap::new(),
            dirty_tokens: Vec::new(),
            session_key: Zeroizing::new(key),
            policy: SecurityPolicy::IndonesiaUuPdpStrict,
            token_format: TokenFormat::Sequential,
        }
    }

    /// Returns the active token format.
    pub fn token_format(&self) -> TokenFormat {
        self.token_format
    }

    /// Sets the active token format (Sequential, CompactHash, StatelessSealed).
    pub fn set_token_format(&mut self, format: TokenFormat) {
        self.token_format = format;
    }

    /// Checks whether stateless sealed-token mode is active.
    pub fn is_stateless_mode(&self) -> bool {
        self.token_format == TokenFormat::StatelessSealed
    }

    /// Enables or disables stateless sealed-token mode.
    pub fn set_stateless_mode(&mut self, enabled: bool) {
        if enabled {
            self.token_format = TokenFormat::StatelessSealed;
        } else {
            self.token_format = TokenFormat::Sequential;
        }
    }

    /// Policy associated with this vault session.
    pub fn policy(&self) -> SecurityPolicy {
        self.policy
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
        let mut mac =
            HmacSha256::new_from_slice(&*self.session_key).expect("HMAC key length valid");
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

        if !ct_eq(siv, &expected_siv_full[..16]) {
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
        if self.token_format == TokenFormat::StatelessSealed {
            return self.create_sealed_token(&tag_prefix, raw_pii);
        }

        let digest = self.compute_hmac(&tag_prefix, raw_pii);
        if let Some(existing) = self.forward_map.get(&digest) {
            return existing.clone();
        }

        let token = match self.token_format {
            TokenFormat::Sequential => {
                let count = self.counters.entry(entity_type.clone()).or_insert(0);
                *count = count.saturating_add(1);
                format!("<{}_{}>", tag_prefix, count)
            }
            TokenFormat::CompactHash => {
                let num = u64::from_be_bytes(digest[..8].try_into().unwrap());
                let base_code = encode_base36(num % 2_176_782_336, 6);
                let mut candidate = format!("<{}_{}>", tag_prefix, base_code);
                if let Some((_, existing_raw)) = self.reverse_map.get(&candidate) {
                    if existing_raw.as_str() != raw_pii.trim() {
                        let ext_code = encode_base36(num % 2_821_109_907_456, 8);
                        candidate = format!("<{}_{}>", tag_prefix, ext_code);
                    }
                }
                candidate
            }
            TokenFormat::StatelessSealed => unreachable!(),
        };

        self.forward_map.insert(digest, token.clone());
        self.reverse_map.insert(
            token.clone(),
            (entity_type, Zeroizing::new(raw_pii.trim().to_string())),
        );
        self.dirty_tokens.push(token.clone());

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

    /// Recursively redacts all string leaves inside a serde_json::Value AST,
    /// leaving JSON keys, numbers, booleans, and null untouched.
    /// Also handles nested JSON-in-JSON string leaves.
    pub fn redact_json_value(&mut self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (_k, v) in map {
                    self.redact_json_value(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for elem in arr {
                    self.redact_json_value(elem);
                }
            }
            serde_json::Value::String(s) => {
                // Check if string leaf itself is nested JSON
                if (s.starts_with('{') && s.ends_with('}'))
                    || (s.starts_with('[') && s.ends_with(']'))
                {
                    if let Ok(mut inner_val) = serde_json::from_str::<serde_json::Value>(s) {
                        self.redact_json_value(&mut inner_val);
                        if let Ok(serialized) = serde_json::to_string(&inner_val) {
                            *s = serialized;
                            return;
                        }
                    }
                }
                *s = self.redact(s);
            }
            _ => {}
        }
    }

    /// Redacts raw PII in string leaves of a JSON payload without corrupting
    /// unquoted numbers, object keys, or structural tokens.
    /// If payload is not valid JSON, falls back to plain string redact.
    pub fn redact_json(&mut self, payload: &str) -> String {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(payload) {
            self.redact_json_value(&mut json_val);
            serde_json::to_string(&json_val).unwrap_or_else(|_| self.redact(payload))
        } else {
            self.redact(payload)
        }
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
                for (j, &b) in bytes.iter().enumerate().skip(start + 1) {
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
        if let Some((_, val)) = self.reverse_map.get(token) {
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
        self.reverse_map.get(token).map(|(_, z)| z.as_str())
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
                    if (s.starts_with('{') && s.ends_with('}'))
                        || (s.starts_with('[') && s.ends_with(']'))
                    {
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
        for (token, (_, raw_val)) in &self.reverse_map {
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

    fn derive_state_subkeys(&self) -> ([u8; 32], [u8; 32]) {
        let mut mac = HmacSha256::new_from_slice(&*self.session_key).expect("Key valid");
        mac.update(b"pii-shield-state-mac-v1");
        let k_mac = mac.finalize().into_bytes().into();

        let mut enc = HmacSha256::new_from_slice(&*self.session_key).expect("Key valid");
        enc.update(b"pii-shield-state-enc-v1");
        let k_enc = enc.finalize().into_bytes().into();

        (k_mac, k_enc)
    }

    fn seal_entry_bytes(
        &self,
        entity_prefix: &str,
        raw_pii: &str,
        token: &str,
        aad: &str,
    ) -> String {
        let (k_mac, k_enc) = self.derive_state_subkeys();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");

        let trimmed = raw_pii.trim();
        let mut plaintext = Vec::with_capacity(entity_prefix.len() + 1 + trimmed.len());
        plaintext.extend_from_slice(entity_prefix.as_bytes());
        plaintext.push(0x00);
        plaintext.extend_from_slice(trimmed.as_bytes());

        // SIV = HMAC(K_state_mac, "PIIE1" || nonce || aad_len || aad || token_len || token || plaintext)[0..16]
        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(b"PIIE1");
        mac.update(&nonce);
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad.as_bytes());
        mac.update(&(token.len() as u64).to_be_bytes());
        mac.update(token.as_bytes());
        mac.update(&plaintext);
        let siv_full = mac.finalize().into_bytes();
        let mut siv = [0u8; 16];
        siv.copy_from_slice(&siv_full[..16]);

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut block_idx = 0u32;
        while ciphertext.len() < plaintext.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(&siv);
            ctr_mac.update(&nonce);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks = ctr_mac.finalize().into_bytes();

            for &b in ks.iter() {
                if ciphertext.len() == plaintext.len() {
                    break;
                }
                let pt = plaintext[ciphertext.len()];
                ciphertext.push(pt ^ b);
            }
            block_idx += 1;
        }

        let mut payload = Vec::with_capacity(32 + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&siv);
        payload.extend_from_slice(&ciphertext);
        format!("PIIE1:{}", hex::encode_upper(payload))
    }

    fn unseal_entry_bytes(
        &self,
        sealed: &str,
        token: &str,
        aad: &str,
    ) -> Result<(EntityType, Zeroizing<String>), SecurityError> {
        if !sealed.starts_with("PIIE1:") {
            return Err(SecurityError::InvalidStateBlob);
        }
        let hex_str = &sealed[6..];
        let Ok(payload) = hex::decode(hex_str) else {
            return Err(SecurityError::InvalidStateBlob);
        };
        if payload.len() < 33 {
            return Err(SecurityError::InvalidStateBlob);
        }

        let (k_mac, k_enc) = self.derive_state_subkeys();
        let nonce = &payload[..16];
        let siv = &payload[16..32];
        let ciphertext = &payload[32..];

        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        let mut block_idx = 0u32;
        while plaintext.len() < ciphertext.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(siv);
            ctr_mac.update(nonce);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks = ctr_mac.finalize().into_bytes();

            for &b in ks.iter() {
                if plaintext.len() == ciphertext.len() {
                    break;
                }
                let ct = ciphertext[plaintext.len()];
                plaintext.push(ct ^ b);
            }
            block_idx += 1;
        }

        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(b"PIIE1");
        mac.update(nonce);
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad.as_bytes());
        mac.update(&(token.len() as u64).to_be_bytes());
        mac.update(token.as_bytes());
        mac.update(&plaintext);
        let expected_siv_full = mac.finalize().into_bytes();

        if !ct_eq(siv, &expected_siv_full[..16]) {
            return Err(SecurityError::InvalidStateBlob);
        }

        let Some(sep_idx) = plaintext.iter().position(|&b| b == 0x00) else {
            return Err(SecurityError::InvalidStateBlob);
        };
        let prefix_str = std::str::from_utf8(&plaintext[..sep_idx])
            .map_err(|_| SecurityError::InvalidStateBlob)?;
        let raw_str = std::str::from_utf8(&plaintext[sep_idx + 1..])
            .map_err(|_| SecurityError::InvalidStateBlob)?;

        let entity_type = EntityType::from_tag_prefix(prefix_str);
        Ok((entity_type, Zeroizing::new(raw_str.to_string())))
    }

    /// Exports all current session entries sealed with the session key and bound to aad.
    pub fn export_sealed_entries(&self, aad: &str) -> AHashMap<String, String> {
        let mut map = AHashMap::with_capacity(self.reverse_map.len());
        for (token, (entity_type, raw_pii)) in &self.reverse_map {
            let sealed =
                self.seal_entry_bytes(entity_type.as_tag_prefix(), raw_pii.as_str(), token, aad);
            map.insert(token.clone(), sealed);
        }
        map
    }

    /// Drains and exports newly created entries since the last sync.
    pub fn drain_dirty_sealed_entries(&mut self, aad: &str) -> AHashMap<String, String> {
        let dirty = std::mem::take(&mut self.dirty_tokens);
        let mut map = AHashMap::with_capacity(dirty.len());
        for token in dirty {
            if let Some((entity_type, raw_pii)) = self.reverse_map.get(&token) {
                let sealed = self.seal_entry_bytes(
                    entity_type.as_tag_prefix(),
                    raw_pii.as_str(),
                    &token,
                    aad,
                );
                map.insert(token, sealed);
            }
        }
        map
    }

    /// Imports and decrypts sealed entries from an iterator of (token, sealed_value).
    /// Enforces conflict detection before applying any mutations.
    pub fn import_sealed_entries<'a, I>(
        &mut self,
        entries: I,
        aad: &str,
    ) -> Result<(), SecurityError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut decrypted = Vec::new();
        for (token, sealed) in entries {
            let (entity_type, raw_val) = self.unseal_entry_bytes(sealed, token, aad)?;
            if let Some((_, existing_raw)) = self.reverse_map.get(token) {
                if existing_raw.as_str() != raw_val.as_str() {
                    return Err(SecurityError::StateConflict {
                        token: token.to_string(),
                    });
                }
            }
            decrypted.push((token.to_string(), entity_type, raw_val));
        }

        for (token, entity_type, raw_val) in decrypted {
            let digest = self.compute_hmac(entity_type.as_tag_prefix(), raw_val.as_str());
            self.forward_map.insert(digest, token.clone());

            if let Some(inner) = token.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
                if let Some(last_us) = inner.rfind('_') {
                    if let Ok(seq_num) = inner[last_us + 1..].parse::<u64>() {
                        let cur = self.counters.entry(entity_type.clone()).or_insert(0);
                        *cur = (*cur).max(seq_num);
                    }
                }
            }

            self.reverse_map.insert(token, (entity_type, raw_val));
        }

        Ok(())
    }

    /// Exports all current session entries as a JSON map of token -> sealed_value.
    pub fn export_sealed_entries_json(&self, aad: &str) -> String {
        let map: std::collections::BTreeMap<String, String> =
            self.export_sealed_entries(aad).into_iter().collect();
        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
    }

    /// Drains and exports newly created entries as a JSON map of token -> sealed_value.
    pub fn drain_dirty_sealed_entries_json(&mut self, aad: &str) -> String {
        let map: std::collections::BTreeMap<String, String> =
            self.drain_dirty_sealed_entries(aad).into_iter().collect();
        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
    }

    /// Imports sealed entries from a JSON map string of {"token": "sealed_value"}.
    pub fn import_sealed_entries_json(
        &mut self,
        json_map: &str,
        aad: &str,
    ) -> Result<(), SecurityError> {
        let map: std::collections::HashMap<String, String> =
            serde_json::from_str(json_map).map_err(|_| SecurityError::InvalidStateBlob)?;
        let entries: Vec<(&str, &str)> =
            map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.import_sealed_entries(entries, aad)
    }

    /// Exports full session state into a single encrypted envelope (PIIS1).
    pub fn export_sealed_state(&self, aad: &str) -> String {
        let (k_mac, k_enc) = self.derive_state_subkeys();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");

        let entries: Vec<VaultSnapshotEntry> = self
            .reverse_map
            .iter()
            .map(|(token, (entity, raw))| VaultSnapshotEntry {
                entity: entity.as_tag_prefix().to_string(),
                token: token.clone(),
                raw: raw.as_str().to_string(),
            })
            .collect();

        let counters: Vec<(String, u64)> = self
            .counters
            .iter()
            .map(|(entity, count)| (entity.as_tag_prefix().to_string(), *count))
            .collect();

        let snapshot = VaultSnapshotV1 {
            v: 1,
            entries,
            counters,
        };

        let plaintext = serde_json::to_vec(&snapshot).expect("Snapshot serializable");

        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(b"PIIS1");
        mac.update(&nonce);
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad.as_bytes());
        mac.update(&plaintext);
        let siv_full = mac.finalize().into_bytes();
        let mut siv = [0u8; 16];
        siv.copy_from_slice(&siv_full[..16]);

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut block_idx = 0u32;
        while ciphertext.len() < plaintext.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(&siv);
            ctr_mac.update(&nonce);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks = ctr_mac.finalize().into_bytes();

            for &b in ks.iter() {
                if ciphertext.len() == plaintext.len() {
                    break;
                }
                let pt = plaintext[ciphertext.len()];
                ciphertext.push(pt ^ b);
            }
            block_idx += 1;
        }

        let mut payload = Vec::with_capacity(32 + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&siv);
        payload.extend_from_slice(&ciphertext);
        format!("PIIS1:{}", hex::encode_upper(payload))
    }

    /// Restores full session state from an encrypted envelope (PIIS1).
    pub fn import_sealed_state(&mut self, sealed: &str, aad: &str) -> Result<(), SecurityError> {
        if !sealed.starts_with("PIIS1:") {
            return Err(SecurityError::InvalidStateBlob);
        }
        let hex_str = &sealed[6..];
        let Ok(payload) = hex::decode(hex_str) else {
            return Err(SecurityError::InvalidStateBlob);
        };
        if payload.len() < 33 {
            return Err(SecurityError::InvalidStateBlob);
        }

        let (k_mac, k_enc) = self.derive_state_subkeys();
        let nonce = &payload[..16];
        let siv = &payload[16..32];
        let ciphertext = &payload[32..];

        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        let mut block_idx = 0u32;
        while plaintext.len() < ciphertext.len() {
            let mut ctr_mac = HmacSha256::new_from_slice(&k_enc).expect("HMAC key valid");
            ctr_mac.update(siv);
            ctr_mac.update(nonce);
            ctr_mac.update(&block_idx.to_be_bytes());
            let ks = ctr_mac.finalize().into_bytes();

            for &b in ks.iter() {
                if plaintext.len() == ciphertext.len() {
                    break;
                }
                let ct = ciphertext[plaintext.len()];
                plaintext.push(ct ^ b);
            }
            block_idx += 1;
        }

        let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key valid");
        mac.update(b"PIIS1");
        mac.update(nonce);
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad.as_bytes());
        mac.update(&plaintext);
        let expected_siv_full = mac.finalize().into_bytes();

        if !ct_eq(siv, &expected_siv_full[..16]) {
            return Err(SecurityError::InvalidStateBlob);
        }

        let snapshot: VaultSnapshotV1 =
            serde_json::from_slice(&plaintext).map_err(|_| SecurityError::InvalidStateBlob)?;
        if snapshot.v != 1 {
            return Err(SecurityError::InvalidStateBlob);
        }

        for entry in &snapshot.entries {
            if let Some((_, existing_raw)) = self.reverse_map.get(&entry.token) {
                if existing_raw.as_str() != entry.raw.as_str() {
                    return Err(SecurityError::StateConflict {
                        token: entry.token.clone(),
                    });
                }
            }
        }

        for entry in snapshot.entries {
            let entity_type = EntityType::from_tag_prefix(&entry.entity);
            let digest = self.compute_hmac(&entry.entity, &entry.raw);
            self.forward_map.insert(digest, entry.token.clone());
            self.reverse_map
                .insert(entry.token, (entity_type, Zeroizing::new(entry.raw)));
        }

        for (entity_prefix, remote_count) in snapshot.counters {
            let entity_type = EntityType::from_tag_prefix(&entity_prefix);
            let cur = self.counters.entry(entity_type).or_insert(0);
            *cur = (*cur).max(remote_count);
        }

        Ok(())
    }

    /// Loads entries from any generic Key-Value or document storage backend.
    pub fn load_from_store<S: PiiVaultStore>(
        &mut self,
        store: &S,
        session_id: &str,
    ) -> Result<(), SecurityError> {
        let entries = store
            .get_entries(session_id)
            .map_err(|_| SecurityError::InvalidStateBlob)?;
        let entry_refs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.import_sealed_entries(entry_refs, session_id)
    }

    /// Flushes all dirty entries created during the current turn to a Key-Value storage backend.
    pub fn flush_to_store<S: PiiVaultStore>(
        &mut self,
        store: &mut S,
        session_id: &str,
    ) -> Result<usize, SecurityError> {
        let dirty = self.drain_dirty_sealed_entries(session_id);
        let count = dirty.len();
        if count > 0 {
            let entries: Vec<(String, String)> = dirty.into_iter().collect();
            store
                .put_entries(session_id, entries)
                .map_err(|_| SecurityError::InvalidStateBlob)?;
        }
        Ok(count)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultSnapshotEntry {
    entity: String,
    token: String,
    raw: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultSnapshotV1 {
    v: u8,
    entries: Vec<VaultSnapshotEntry>,
    counters: Vec<(String, u64)>,
}

/// Pluggable storage trait for persisting sealed PII entries across distributed workers.
pub trait PiiVaultStore {
    type Error: std::fmt::Debug;
    fn get_entries(&self, session_id: &str) -> Result<Vec<(String, String)>, Self::Error>;
    fn put_entries(
        &mut self,
        session_id: &str,
        entries: Vec<(String, String)>,
    ) -> Result<(), Self::Error>;
}

/// In-memory reference store for testing or process-level cache sharing.
#[derive(Default, Debug, Clone)]
pub struct InMemoryVaultStore {
    storage: AHashMap<String, AHashMap<String, String>>,
}

impl InMemoryVaultStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PiiVaultStore for InMemoryVaultStore {
    type Error = std::convert::Infallible;

    fn get_entries(&self, session_id: &str) -> Result<Vec<(String, String)>, Self::Error> {
        let entries = match self.storage.get(session_id) {
            Some(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            None => Vec::new(),
        };
        Ok(entries)
    }

    fn put_entries(
        &mut self,
        session_id: &str,
        entries: Vec<(String, String)>,
    ) -> Result<(), Self::Error> {
        let map = self.storage.entry(session_id.to_string()).or_default();
        for (k, v) in entries {
            map.insert(k, v);
        }
        Ok(())
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
            (
                EntityType::Email,
                Zeroizing::new("user+<ID_NIK_1>@example.com".to_string()),
            ),
        );
        vault.reverse_map.insert(
            "<ID_NIK_1>".to_string(),
            (
                EntityType::IdNik,
                Zeroizing::new("3573012203950001".to_string()),
            ),
        );

        let rehydrated = vault.rehydrate("Send to <EMAIL_1>");
        assert_eq!(rehydrated, "Send to user+<ID_NIK_1>@example.com");
    }

    #[test]
    fn test_compact_hash_format() {
        let key = [11u8; 32];
        let mut vault = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        vault.set_token_format(TokenFormat::CompactHash);

        let masked = vault.redact("NIK: 3573012203950001 dan 081234567890");
        assert!(masked.contains("<ID_NIK_"));
        assert!(masked.contains("<PHONE_ID_"));

        // Extract token
        let rehydrated = vault.rehydrate(&masked);
        assert_eq!(rehydrated, "NIK: 3573012203950001 dan 081234567890");

        // Verify determinism: fresh vault with same key generates identical token
        let mut vault2 = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        vault2.set_token_format(TokenFormat::CompactHash);
        let masked2 = vault2.redact("NIK: 3573012203950001");
        assert_eq!(masked.split(' ').nth(1), masked2.split(' ').nth(1));
    }

    #[test]
    fn test_distributed_kv_concurrent_pods_lock_free() {
        let cluster_key = [88u8; 32];
        let session_id = "session:order_99";
        let mut shared_store = InMemoryVaultStore::new();

        // Pod A starts in CompactHash mode and redacts Alice's NIK
        let mut pod_a =
            PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
        pod_a.set_token_format(TokenFormat::CompactHash);
        let masked_a = pod_a.redact("Customer Alice NIK 3573012203950001");
        assert!(masked_a.contains("<ID_NIK_"));

        // Pod B starts concurrently and redacts Bob's Phone
        let mut pod_b =
            PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
        pod_b.set_token_format(TokenFormat::CompactHash);
        let masked_b = pod_b.redact("Customer Bob Phone 081234567890");
        assert!(masked_b.contains("<PHONE_ID_"));

        // Both pods flush their dirty entries to shared store (commutative HSET)
        let flushed_a = pod_a.flush_to_store(&mut shared_store, session_id).unwrap();
        assert_eq!(flushed_a, 1);
        let flushed_b = pod_b.flush_to_store(&mut shared_store, session_id).unwrap();
        assert_eq!(flushed_b, 1);

        // Pod C (egress / tool runner) starts fresh and loads all entries
        let mut pod_c =
            PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, cluster_key);
        pod_c.load_from_store(&shared_store, session_id).unwrap();

        // Pod C cleanly rehydrates both Alice and Bob without conflicts
        let restored_a = pod_c.rehydrate(&masked_a);
        assert_eq!(restored_a, "Customer Alice NIK 3573012203950001");
        let restored_b = pod_c.rehydrate(&masked_b);
        assert_eq!(restored_b, "Customer Bob Phone 081234567890");
    }

    #[test]
    fn test_aad_and_token_binding_tamper_defense() {
        let key = [55u8; 32];
        let mut vault_a = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        let masked = vault_a.redact("NIK 3573012203950001");
        let token = masked.strip_prefix("NIK ").unwrap();

        let entries = vault_a.export_sealed_entries("session:alice");
        let sealed_val = entries.get(token).unwrap();

        // 1. Importing under wrong AAD (session:bob) must fail
        let mut vault_b = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        let bad_import =
            vault_b.import_sealed_entries(vec![(token, sealed_val.as_str())], "session:bob");
        assert_eq!(bad_import, Err(SecurityError::InvalidStateBlob));

        // 2. Importing with swapped token key must fail
        let swapped_token = "<EMAIL_1>";
        let bad_swap = vault_b
            .import_sealed_entries(vec![(swapped_token, sealed_val.as_str())], "session:alice");
        assert_eq!(bad_swap, Err(SecurityError::InvalidStateBlob));

        // 3. Importing with correct AAD and token succeeds
        let good_import =
            vault_b.import_sealed_entries(vec![(token, sealed_val.as_str())], "session:alice");
        assert!(good_import.is_ok());
        assert_eq!(vault_b.rehydrate(token), "3573012203950001");
    }

    #[test]
    fn test_sealed_state_snapshot_full() {
        let key = [33u8; 32];
        let mut vault_a = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        let _ = vault_a.redact("NIK 3573012203950001");
        let _ = vault_a.redact("Email fitra@jotaralab.com");

        let blob = vault_a.export_sealed_state("session:99");
        assert!(blob.starts_with("PIIS1:"));

        // Import into fresh vault_b
        let mut vault_b = PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        vault_b.import_sealed_state(&blob, "session:99").unwrap();
        assert_eq!(vault_b.rehydrate("<ID_NIK_1>"), "3573012203950001");
        assert_eq!(vault_b.rehydrate("<EMAIL_1>"), "fitra@jotaralab.com");

        // Next redacted NIK becomes <ID_NIK_2> because counter was preserved
        let next_nik = vault_b.redact("NIK 3573012902960001");
        assert!(next_nik.contains("<ID_NIK_2>"));

        // Conflict detection: import snapshot with conflicting token mapping
        let mut conflicting_vault =
            PiiSessionVault::with_key(SecurityPolicy::IndonesiaUuPdpStrict, key);
        let _ = conflicting_vault.redact("NIK 3573012902960001"); // Gets <ID_NIK_1> for a DIFFERENT NIK
        let conflict_err = conflicting_vault.import_sealed_state(&blob, "session:99");
        assert!(matches!(
            conflict_err,
            Err(SecurityError::StateConflict { .. })
        ));
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

    #[test]
    fn test_redact_json_preserves_numeric_and_structural_fields() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        let json_input = r#"{"id":3573012203950001,"user":{"nik":"3573012203950001","email":"fitra@jotaralab.com","active":true,"count":42}}"#;

        let redacted = vault.redact_json(json_input);
        // "id": 3573012203950001 must stay an unquoted number!
        assert!(redacted.contains(r#""id":3573012203950001"#));
        // String fields must be redacted
        assert!(redacted.contains(r#""nik":"<ID_NIK_1>""#));
        assert!(redacted.contains(r#""email":"<EMAIL_1>""#));
        assert!(redacted.contains(r#""active":true"#));

        // Test nested JSON string
        let nested_input = r#"{"content":"{\"nik\":\"3573012203950001\"}"}"#;
        let nested_redacted = vault.redact_json(nested_input);
        assert!(nested_redacted.contains("<ID_NIK_1>"));
    }

    #[test]
    fn test_from_catalog_with_key() {
        let catalog = PiiCatalog::with_locales(&["global", "id"]).unwrap();
        let key = [99u8; 32];
        let mut vault = PiiSessionVault::from_catalog_with_key(catalog, key);
        vault.set_stateless_mode(true);
        assert!(vault.is_stateless_mode());

        let scrubbed = vault.redact("NIK: 3573012203950001");
        assert!(scrubbed.starts_with("NIK: <PII:ID_NIK:"));

        let catalog_b = PiiCatalog::with_locales(&["global", "id"]).unwrap();
        let vault_b = PiiSessionVault::from_catalog_with_key(catalog_b, key);
        let restored = vault_b.rehydrate(&scrubbed);
        assert_eq!(restored, "NIK: 3573012203950001");
    }
}
