use pii_core::{PiiCatalog, PiiSessionVault, SecurityPolicy, StreamingRehydrator, ToolTrustLevel};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Parses a comma-separated locale CSV, rejecting empty segments the same way
/// `pii-ffi`'s `locale_names_from_csv` does.
fn locale_names_from_csv(locales: &str) -> Result<Vec<&str>, JsError> {
    let segs = locales.split(',').map(|s| s.trim()).collect::<Vec<&str>>();
    if segs.iter().any(|s| s.is_empty()) {
        return Err(JsError::new(&format!(
            "Invalid locales '{}': empty segments are not allowed (use 'global,id')",
            locales
        )));
    }
    Ok(segs)
}

fn catalog_from_locales(locales: &str) -> Result<PiiCatalog, JsError> {
    let loc_vec = locale_names_from_csv(locales)?;
    PiiCatalog::with_locales(&loc_vec)
        .map_err(|e| JsError::new(&format!("Invalid locales '{}': {}", locales, e)))
}

#[wasm_bindgen]
pub struct WasmPiiSession {
    inner: PiiSessionVault,
}

impl Default for WasmPiiSession {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmPiiSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict),
        }
    }

    #[wasm_bindgen(js_name = withLocales)]
    pub fn with_locales(locales: &str) -> Result<WasmPiiSession, JsError> {
        let catalog = catalog_from_locales(locales)?;
        // Fail closed: an empty (0-rule) catalog is rejected.
        PiiSessionVault::try_from_catalog(catalog)
            .map_err(|e| JsError::new(&format!("Failed to compile PII catalog: {}", e)))
            .map(|inner| Self { inner })
    }

    #[wasm_bindgen(js_name = withLocalesAndKey)]
    pub fn with_locales_and_key(locales: &str, key: &[u8]) -> Result<WasmPiiSession, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("Session key must be exactly 32 bytes"));
        }
        let mut key_arr = Zeroizing::new([0u8; 32]);
        key_arr.copy_from_slice(key);

        let catalog = catalog_from_locales(locales)?;
        PiiSessionVault::try_from_catalog_with_key(catalog, *key_arr)
            .map_err(|e| JsError::new(&format!("Failed to compile PII catalog: {}", e)))
            .map(|inner| Self { inner })
    }

    /// Builds a vault from custom TOML rules, optionally with a 32-byte key.
    #[wasm_bindgen(js_name = withCustomToml)]
    pub fn with_custom_toml(toml: &str, key: Option<Vec<u8>>) -> Result<WasmPiiSession, JsError> {
        build_custom_toml_vault(toml, key)
            .map(|inner| Self { inner })
            .map_err(|msg| JsError::new(&msg))
    }

    #[wasm_bindgen(js_name = setStatelessMode)]
    pub fn set_stateless_mode(&mut self, enabled: bool) {
        self.inner.set_stateless_mode(enabled);
    }

    #[wasm_bindgen(js_name = isStatelessMode)]
    pub fn is_stateless_mode(&self) -> bool {
        self.inner.is_stateless_mode()
    }

    #[wasm_bindgen(js_name = setTokenFormat)]
    pub fn set_token_format(&mut self, format_id: u8) -> Result<(), JsError> {
        let format = match format_id {
            0 => pii_core::TokenFormat::Sequential,
            1 => pii_core::TokenFormat::CompactHash,
            2 => pii_core::TokenFormat::StatelessSealed,
            other => {
                return Err(JsError::new(&format!(
                    "Invalid token format id {}: expected 0 (sequential), 1 (compact-hash), or 2 (stateless-sealed)",
                    other
                )))
            }
        };
        self.inner.set_token_format(format);
        Ok(())
    }

    #[wasm_bindgen(js_name = exportSealedEntriesJson)]
    pub fn export_sealed_entries_json(&self, aad: &str) -> String {
        self.inner.export_sealed_entries_json(aad)
    }

    #[wasm_bindgen(js_name = drainDirtySealedEntriesJson)]
    pub fn drain_dirty_sealed_entries_json(&mut self, aad: &str) -> String {
        self.inner.drain_dirty_sealed_entries_json(aad)
    }

    /// Non-destructive snapshot for safe async persistence: persist the JSON,
    /// then call `clearDirtyTokens` only after the write succeeds.
    #[wasm_bindgen(js_name = sealDirtySealedEntriesJson)]
    pub fn seal_dirty_sealed_entries_json(&self, aad: &str) -> String {
        self.inner.seal_dirty_entries_json(aad)
    }

    #[wasm_bindgen(js_name = clearDirtyTokens)]
    pub fn clear_dirty_tokens(&mut self, tokens_json: &str) -> Result<(), JsError> {
        let tokens: Vec<String> = serde_json::from_str(tokens_json)
            .map_err(|e| JsError::new(&format!("Invalid token list: {}", e)))?;
        self.inner.clear_dirty_tokens(&tokens);
        Ok(())
    }

    #[wasm_bindgen(js_name = importSealedEntriesJson)]
    pub fn import_sealed_entries_json(&mut self, json_map: &str, aad: &str) -> Result<(), JsError> {
        self.inner
            .import_sealed_entries_json(json_map, aad)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = exportSealedState)]
    pub fn export_sealed_state(&self, aad: &str) -> String {
        self.inner.export_sealed_state(aad)
    }

    #[wasm_bindgen(js_name = importSealedState)]
    pub fn import_sealed_state(&mut self, sealed: &str, aad: &str) -> Result<(), JsError> {
        self.inner
            .import_sealed_state(sealed, aad)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn redact(&mut self, text: &str) -> String {
        self.inner.redact(text)
    }

    #[wasm_bindgen(js_name = redactJson)]
    pub fn redact_json(&mut self, payload: &str) -> String {
        self.inner.redact_json(payload)
    }

    #[wasm_bindgen]
    pub fn rehydrate(&self, text: &str) -> String {
        self.inner.rehydrate(text)
    }

    #[wasm_bindgen(js_name = rehydrateForTool)]
    pub fn rehydrate_for_tool(&self, payload: &str, is_trusted: bool) -> Result<String, JsError> {
        let trust_level = if is_trusted {
            ToolTrustLevel::InternalTrusted
        } else {
            ToolTrustLevel::ExternalUntrusted
        };
        self.inner
            .rehydrate_for_tool(payload, trust_level)
            .map_err(|e| match e {
                pii_core::SecurityError::ExfiltrationBlocked { token } => {
                    JsError::new(&format!("PII Exfiltration Blocked: {}", token))
                }
                other => JsError::new(&other.to_string()),
            })
    }
}

#[wasm_bindgen]
pub struct WasmStreamingRehydrator {
    inner: StreamingRehydrator,
}

impl Default for WasmStreamingRehydrator {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmStreamingRehydrator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: StreamingRehydrator::new(),
        }
    }

    #[wasm_bindgen(js_name = pushChunk)]
    pub fn push_chunk(&mut self, chunk: &str, session: &WasmPiiSession) -> String {
        self.inner.push_chunk(chunk, &session.inner)
    }

    #[wasm_bindgen]
    pub fn flush(&mut self, session: &WasmPiiSession) -> String {
        self.inner.flush(&session.inner)
    }
}

fn build_custom_toml_vault(toml: &str, key: Option<Vec<u8>>) -> Result<PiiSessionVault, String> {
    let key = key.map(Zeroizing::new);
    let mut catalog = PiiCatalog::new();
    catalog
        .merge_toml_str(toml)
        .map_err(|e| format!("Invalid TOML rules: {}", e))?;
    if catalog.rules.is_empty() {
        return Err("Catalog Error: catalog contains zero rules (fail-closed)".to_string());
    }
    match key {
        Some(key) => {
            if key.len() != 32 {
                return Err("Session key must be exactly 32 bytes".to_string());
            }
            let key_arr = Zeroizing::new({
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                k
            });
            PiiSessionVault::try_from_catalog_with_key(catalog, *key_arr)
                .map_err(|e| format!("Failed to compile PII catalog: {}", e))
        }
        None => PiiSessionVault::try_from_catalog(catalog)
            .map_err(|e| format!("Failed to compile PII catalog: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_custom_toml_rejects_zero_rules() {
        let empty_rules_toml = r#"
locale = "custom"
name = "Empty Custom Catalog"
rules = []
"#;
        let err = match build_custom_toml_vault(empty_rules_toml, None) {
            Ok(_) => panic!("zero-rule TOML catalog must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("zero rules"),
            "expected zero-rules error message, got: {err}"
        );
    }
}
