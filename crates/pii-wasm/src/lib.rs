use pii_core::{PiiCatalog, PiiSessionVault, SecurityPolicy, StreamingRehydrator, ToolTrustLevel};
use wasm_bindgen::prelude::*;

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

    #[wasm_bindgen]
    pub fn with_locales(locales: &str) -> Self {
        let loc_vec: Vec<&str> = locales.split(',').map(|s| s.trim()).collect();
        let catalog = PiiCatalog::with_locales(&loc_vec).unwrap_or_default();
        Self {
            inner: PiiSessionVault::from_catalog(catalog),
        }
    }

    #[wasm_bindgen(js_name = withLocalesAndKey)]
    pub fn with_locales_and_key(locales: &str, key: &[u8]) -> Result<WasmPiiSession, JsValue> {
        if key.len() != 32 {
            return Err(JsValue::from_str("Session key must be exactly 32 bytes"));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);

        let loc_vec: Vec<&str> = locales.split(',').map(|s| s.trim()).collect();
        let catalog = PiiCatalog::with_locales(&loc_vec).unwrap_or_default();
        Ok(Self {
            inner: PiiSessionVault::from_catalog_with_key(catalog, key_arr),
        })
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
    pub fn set_token_format(&mut self, format_id: u8) {
        let format = match format_id {
            1 => pii_core::TokenFormat::CompactHash,
            2 => pii_core::TokenFormat::StatelessSealed,
            _ => pii_core::TokenFormat::Sequential,
        };
        self.inner.set_token_format(format);
    }

    #[wasm_bindgen(js_name = exportSealedEntriesJson)]
    pub fn export_sealed_entries_json(&self, aad: &str) -> String {
        self.inner.export_sealed_entries_json(aad)
    }

    #[wasm_bindgen(js_name = drainDirtySealedEntriesJson)]
    pub fn drain_dirty_sealed_entries_json(&mut self, aad: &str) -> String {
        self.inner.drain_dirty_sealed_entries_json(aad)
    }

    #[wasm_bindgen(js_name = importSealedEntriesJson)]
    pub fn import_sealed_entries_json(&mut self, json_map: &str, aad: &str) -> Result<(), JsValue> {
        self.inner
            .import_sealed_entries_json(json_map, aad)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = exportSealedState)]
    pub fn export_sealed_state(&self, aad: &str) -> String {
        self.inner.export_sealed_state(aad)
    }

    #[wasm_bindgen(js_name = importSealedState)]
    pub fn import_sealed_state(&mut self, sealed: &str, aad: &str) -> Result<(), JsValue> {
        self.inner
            .import_sealed_state(sealed, aad)
            .map_err(|e| JsValue::from_str(&e.to_string()))
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
    pub fn rehydrate_for_tool(&self, payload: &str, is_trusted: bool) -> Result<String, JsValue> {
        let trust_level = if is_trusted {
            ToolTrustLevel::InternalTrusted
        } else {
            ToolTrustLevel::ExternalUntrusted
        };
        self.inner
            .rehydrate_for_tool(payload, trust_level)
            .map_err(|e| match e {
                pii_core::SecurityError::ExfiltrationBlocked { token } => {
                    JsValue::from_str(&format!("PII Exfiltration Blocked: {}", token))
                }
                other => JsValue::from_str(&other.to_string()),
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
