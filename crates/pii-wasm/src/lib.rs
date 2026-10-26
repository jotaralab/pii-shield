use pii_core::{PiiSessionVault, SecurityPolicy};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmPiiSession {
    inner: PiiSessionVault,
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
    pub fn redact(&mut self, text: &str) -> String {
        self.inner.redact(text)
    }

    #[wasm_bindgen]
    pub fn rehydrate(&self, text: &str) -> String {
        self.inner.rehydrate(text)
    }
}
