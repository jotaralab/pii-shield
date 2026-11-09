#![allow(clippy::missing_safety_doc)]

use pii_core::{
    PiiCatalog, PiiSessionVault, SecurityError, SecurityPolicy, StreamingRehydrator, ToolTrustLevel,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

/// Opaque thread-safe vault handle.
///
/// Uses an `RwLock` so concurrent read-only calls (rehydration, sealed-state
/// export, streaming pushes) from Go goroutines or OS threads do not
/// serialize exclusively against each other.
pub struct PiiVaultHandle(pub RwLock<PiiSessionVault>);

/// Opaque streaming rehydrator handle.
pub struct PiiStreamHandle(pub Mutex<StreamingRehydrator>);

/// Reads the locales selection into a vector of canonical locale names.
///
/// `None` (null pointer) means the default "global,id" set — only a NULL
/// pointer selects the default. A non-NULL CSV must be valid UTF-8, non-empty
/// after trimming, and contain no empty comma-separated segment; otherwise
/// `None` is returned so callers fail closed (an empty segment such as in
/// `"global,,id"` must never silently fall back to the default set).
unsafe fn locale_names_from_csv(locales: *const c_char) -> Option<Vec<String>> {
    if locales.is_null() {
        return Some(vec!["global".to_string(), "id".to_string()]);
    }
    let loc_str = CStr::from_ptr(locales).to_str().ok()?;
    if loc_str.trim().is_empty() {
        return None;
    }
    let loc_vec: Vec<String> = loc_str.split(',').map(|s| s.trim().to_string()).collect();
    if loc_vec.iter().any(|s| s.is_empty()) {
        // Reject empty segments (e.g. "global,,id") instead of dropping them.
        return None;
    }
    Some(loc_vec)
}

fn catalog_with_locale_refs(locs: &[String]) -> Result<PiiCatalog, pii_core::CatalogError> {
    let refs: Vec<&str> = locs.iter().map(String::as_str).collect();
    PiiCatalog::with_locales(&refs)
}

/// Builds a vault from a catalog or fails closed (null pointer). Any of the
/// constructors that resolve a catalog funnel through this helper so an
/// invalid catalog can never silently become a useless 0-rule vault.
fn vault_from_catalog_fail_closed(
    catalog: PiiCatalog,
    key: Option<[u8; 32]>,
) -> *mut PiiVaultHandle {
    // Reject empty catalogs: a 0-rule vault redacts nothing and must never
    // be handed to a caller as a valid handle.
    if catalog.rules.is_empty() {
        return ptr::null_mut();
    }
    // Fallible vault construction: parallel to the panicking path, an
    // engine-compile error must surface as NULL, not a panic across the ABI.
    // The key spends its life in a `Zeroizing` buffer inside the vault, and
    // any local buffer is zeroized on scope exit.
    let built = match key {
        Some(k) => {
            let k_buf = Zeroizing::new(k);
            PiiSessionVault::try_from_catalog_with_key(catalog, *k_buf)
        }
        None => PiiSessionVault::try_from_catalog(catalog),
    };
    match built {
        Ok(vault) => Box::into_raw(Box::new(PiiVaultHandle(RwLock::new(vault)))),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn pii_vault_new() -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        let vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        Box::into_raw(Box::new(PiiVaultHandle(RwLock::new(vault))))
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_new_with_locales(locales: *const c_char) -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        // Fail closed: an unknown locale must not silently produce an
        // empty (0-rule) catalog that redacts nothing.
        let loc_vec = match locale_names_from_csv(locales) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let catalog = match catalog_with_locale_refs(&loc_vec) {
            Ok(c) => c,
            Err(_) => return ptr::null_mut(),
        };
        vault_from_catalog_fail_closed(catalog, None)
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_new_with_key(
    policy_id: u8,
    key: *const u8,
    key_len: usize,
) -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        if key.is_null() || key_len != 32 {
            return ptr::null_mut();
        }
        let mut key_bytes = [0u8; 32];
        ptr::copy_nonoverlapping(key, key_bytes.as_mut_ptr(), 32);

        // Strict policy validation: unknown ids fail closed.
        let policy = match policy_id {
            0 => SecurityPolicy::IndonesiaUuPdpStrict,
            1 => SecurityPolicy::StandardGlobal,
            _ => return ptr::null_mut(),
        };
        let vault = PiiSessionVault::with_key(policy, key_bytes);
        Box::into_raw(Box::new(PiiVaultHandle(RwLock::new(vault))))
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_new_with_locales_and_key(
    locales: *const c_char,
    key: *const u8,
    key_len: usize,
) -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        if key.is_null() || key_len != 32 {
            return ptr::null_mut();
        }
        let mut key_bytes = [0u8; 32];
        ptr::copy_nonoverlapping(key, key_bytes.as_mut_ptr(), 32);

        let loc_vec = match locale_names_from_csv(locales) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };
        let catalog = match catalog_with_locale_refs(&loc_vec) {
            Ok(c) => c,
            Err(_) => return ptr::null_mut(),
        };
        vault_from_catalog_fail_closed(catalog, Some(key_bytes))
    }))
    .unwrap_or(ptr::null_mut())
}

/// Creates a vault from built-in locales plus a custom runtime TOML rule set.
///
/// Returns NULL on any invalid input. All inputs are validated **before** any
/// CSPRNG key is generated, so a failed call never burns entropy on a doomed
/// construction.
///
/// Locales: NULL selects the default "global,id" set; a non-NULL CSV must be
/// valid UTF-8, non-empty, and free of empty comma-separated segments.
///
/// Key handling (fail closed):
/// - `key_ptr.is_null() && key_len == 0`: a CSPRNG session key is generated.
/// - `!key_ptr.is_null() && key_len == 32`: the provided key is used.
/// - Anything else returns NULL.
///
/// TOML: must be non-NULL, non-empty, valid, and define at least one rule.
/// The custom rules are merged on top of the built-in locale rules; a rule
/// whose id already exists overrides the built-in definition.
#[no_mangle]
pub unsafe extern "C" fn pii_vault_with_custom_toml(
    locales_csv: *const c_char,
    custom_toml: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
) -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        // 1. Locales.
        let loc_vec = match locale_names_from_csv(locales_csv) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };

        // 2. Custom TOML is mandatory here; empty, whitespace-only, or
        //    rule-less TOML fails closed (as does invalid TOML/regex).
        if custom_toml.is_null() {
            return ptr::null_mut();
        }
        let toml_str = match CStr::from_ptr(custom_toml).to_str() {
            Ok(s) if !s.trim().is_empty() => s,
            _ => return ptr::null_mut(),
        };
        let parsed: pii_core::LocaleCatalog = match toml::from_str(toml_str) {
            Ok(p) => p,
            Err(_) => return ptr::null_mut(),
        };
        if parsed.rules.is_empty() {
            return ptr::null_mut();
        }

        // 3. Built-in catalog first, then the custom rules merged in.
        let mut catalog = match catalog_with_locale_refs(&loc_vec) {
            Ok(c) => c,
            Err(_) => return ptr::null_mut(),
        };
        if catalog.merge_toml_str(toml_str).is_err() {
            return ptr::null_mut();
        }

        // 4. Key policy — validated now, CSPRNG generation only on success.
        let key: Option<[u8; 32]> = if key_ptr.is_null() && key_len == 0 {
            let mut generated = [0u8; 32];
            if getrandom::getrandom(&mut generated).is_err() {
                return ptr::null_mut();
            }
            Some(generated)
        } else if !key_ptr.is_null() && key_len == 32 {
            let mut key_bytes = [0u8; 32];
            ptr::copy_nonoverlapping(key_ptr, key_bytes.as_mut_ptr(), 32);
            Some(key_bytes)
        } else {
            return ptr::null_mut();
        };

        vault_from_catalog_fail_closed(catalog, key)
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_set_token_format(ptr: *mut PiiVaultHandle, format_id: u8) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = &*ptr;
        if let Ok(mut vault) = handle.0.write() {
            let format = match format_id {
                0 => pii_core::TokenFormat::Sequential,
                1 => pii_core::TokenFormat::CompactHash,
                2 => pii_core::TokenFormat::StatelessSealed,
                // Strict: an invalid format must not silently overwrite the
                // current setting with Sequential.
                _ => return,
            };
            vault.set_token_format(format);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_set_stateless_mode(ptr: *mut PiiVaultHandle, enabled: bool) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = &*ptr;
        if let Ok(mut vault) = handle.0.write() {
            vault.set_stateless_mode(enabled);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_export_sealed_entries_json(
    ptr: *const PiiVaultHandle,
    aad: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return ptr::null_mut();
        }
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };
        let handle = &*ptr;
        let vault = match handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let json_str = vault.export_sealed_entries_json(aad_str);
        match CString::new(json_str) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_drain_dirty_sealed_entries_json(
    ptr: *mut PiiVaultHandle,
    aad: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return ptr::null_mut();
        }
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let json_str = vault.drain_dirty_sealed_entries_json(aad_str);
        match CString::new(json_str) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_seal_dirty_sealed_entries_json(
    ptr: *const PiiVaultHandle,
    aad: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return ptr::null_mut();
        }
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };
        let handle = &*ptr;
        let vault = match handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        match CString::new(vault.seal_dirty_entries_json(aad_str)) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Reports whether the vault is currently in stateless sealed-token mode.
#[no_mangle]
pub unsafe extern "C" fn pii_vault_is_stateless_mode(ptr: *const PiiVaultHandle) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return false;
        }
        let handle = &*ptr;
        match handle.0.read() {
            Ok(vault) => vault.is_stateless_mode(),
            Err(_) => false,
        }
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_clear_dirty_tokens(
    ptr: *mut PiiVaultHandle,
    tokens_json: *const c_char,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || tokens_json.is_null() {
            return false;
        }
        let tokens_str = match CStr::from_ptr(tokens_json).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let tokens: Vec<String> = match serde_json::from_str(tokens_str) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return false,
        };
        vault.clear_dirty_tokens(&tokens);
        true
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_import_sealed_entries_json(
    ptr: *mut PiiVaultHandle,
    json_map: *const c_char,
    aad: *const c_char,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || json_map.is_null() {
            return false;
        }
        let map_str = match CStr::from_ptr(json_map).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return false,
            }
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return false,
        };
        vault.import_sealed_entries_json(map_str, aad_str).is_ok()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_export_sealed_state(
    ptr: *const PiiVaultHandle,
    aad: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return ptr::null_mut();
        }
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };
        let handle = &*ptr;
        let vault = match handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let blob = vault.export_sealed_state(aad_str);
        match CString::new(blob) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_import_sealed_state(
    ptr: *mut PiiVaultHandle,
    sealed: *const c_char,
    aad: *const c_char,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || sealed.is_null() {
            return false;
        }
        let sealed_str = match CStr::from_ptr(sealed).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let aad_str = if aad.is_null() {
            ""
        } else {
            match CStr::from_ptr(aad).to_str() {
                Ok(s) => s,
                Err(_) => return false,
            }
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return false,
        };
        vault.import_sealed_state(sealed_str, aad_str).is_ok()
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_free(ptr: *mut PiiVaultHandle) {
    if !ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(Box::from_raw(ptr));
        }));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_redact(
    ptr: *mut PiiVaultHandle,
    input: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || input.is_null() {
            return ptr::null_mut();
        }
        let c_str = match CStr::from_ptr(input).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let redacted = vault.redact(c_str);
        match CString::new(redacted) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_redact_json(
    ptr: *mut PiiVaultHandle,
    payload: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || payload.is_null() {
            return ptr::null_mut();
        }
        let c_str = match CStr::from_ptr(payload).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let handle = &*ptr;
        let mut vault = match handle.0.write() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let redacted = vault.redact_json(c_str);
        match CString::new(redacted) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_rehydrate(
    ptr: *const PiiVaultHandle,
    input: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || input.is_null() {
            return ptr::null_mut();
        }
        let c_str = match CStr::from_ptr(input).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let handle = &*ptr;
        let vault = match handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let rehydrated = vault.rehydrate(c_str);
        match CString::new(rehydrated) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_rehydrate_for_tool(
    ptr: *const PiiVaultHandle,
    payload: *const c_char,
    is_trusted: bool,
) -> *mut c_char {
    pii_vault_rehydrate_for_tool_ex(ptr, payload, is_trusted, ptr::null_mut())
}

/// Extended variant of [`pii_vault_rehydrate_for_tool`] that distinguishes an
/// ACL exfiltration block from any other failure via `err_out`.
///
/// Contract (when `err_out` is a valid pointer to `char *`):
/// - ACL block: returns NULL and sets `*err_out` to a caller-owned
///   NUL-terminated UTF-8 token string (free via `pii_string_free`).
/// - Input or operational failure (NULL handle/payload, non-UTF-8 payload,
///   lock failure): returns NULL and `*err_out` is NULL.
///
/// `*err_out` is zeroed unconditionally at entry. The legacy
/// [`pii_vault_rehydrate_for_tool`] remains for ABI compatibility and keeps
/// returning NULL for every failure mode.
#[no_mangle]
pub unsafe extern "C" fn pii_vault_rehydrate_for_tool_ex(
    ptr: *const PiiVaultHandle,
    payload: *const c_char,
    is_trusted: bool,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        // Zero the error slot unconditionally up front: even a NULL handle or
        // payload must leave *err_out == NULL (input failure), so callers can
        // distinguish ACL blocks from operational failures.
        if !err_out.is_null() {
            *err_out = ptr::null_mut();
        }
        if ptr.is_null() || payload.is_null() {
            return ptr::null_mut();
        }
        let c_str = match CStr::from_ptr(payload).to_str() {
            Ok(s) => s,
            // Non-UTF-8 payload: not an exfiltration event, just unusable.
            Err(_) => return ptr::null_mut(),
        };
        let handle = &*ptr;
        let vault = match handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let trust_level = if is_trusted {
            ToolTrustLevel::InternalTrusted
        } else {
            ToolTrustLevel::ExternalUntrusted
        };
        match vault.rehydrate_for_tool(c_str, trust_level) {
            Ok(rehydrated) => match CString::new(rehydrated) {
                Ok(s) => s.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(err) => {
                if !err_out.is_null() {
                    // Only ExfiltrationBlocked carries a meaningful token;
                    // for other security failures a space-containing message
                    // would still give operators the offending token.
                    if let SecurityError::ExfiltrationBlocked { token }
                    | SecurityError::StateConflict { token } = &err
                    {
                        if let Ok(c_token) = CString::new(token.as_str()) {
                            *err_out = c_token.into_raw();
                        }
                    }
                }
                ptr::null_mut() // Blocked
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(CString::from_raw(s));
        }));
    }
}

// Streaming Rehydrator C-ABI
#[no_mangle]
pub extern "C" fn pii_stream_new() -> *mut PiiStreamHandle {
    catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(PiiStreamHandle(Mutex::new(
            StreamingRehydrator::new(),
        ))))
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_stream_push_chunk(
    stream_ptr: *mut PiiStreamHandle,
    vault_ptr: *const PiiVaultHandle,
    chunk: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if stream_ptr.is_null() || vault_ptr.is_null() || chunk.is_null() {
            return ptr::null_mut();
        }
        let chunk_str = match CStr::from_ptr(chunk).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let stream_handle = &*stream_ptr;
        let mut stream = match stream_handle.0.lock() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let vault_handle = &*vault_ptr;
        let vault = match vault_handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };

        let output = stream.push_chunk(chunk_str, &vault);
        match CString::new(output) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_stream_flush(
    stream_ptr: *mut PiiStreamHandle,
    vault_ptr: *const PiiVaultHandle,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if stream_ptr.is_null() || vault_ptr.is_null() {
            return ptr::null_mut();
        }
        let stream_handle = &*stream_ptr;
        let mut stream = match stream_handle.0.lock() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        let vault_handle = &*vault_ptr;
        let vault = match vault_handle.0.read() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };

        let output = stream.flush(&vault);
        match CString::new(output) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_stream_free(stream_ptr: *mut PiiStreamHandle) {
    if !stream_ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(Box::from_raw(stream_ptr));
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pii_core::SecurityError;

    #[test]
    fn test_ffi_roundtrip_stateless_and_json() {
        unsafe {
            let key = [77u8; 32];
            let v1 = pii_vault_new_with_key(0, key.as_ptr(), key.len());
            assert!(!v1.is_null());
            pii_vault_set_stateless_mode(v1, true);

            let json_input = CString::new(r#"{"nik":"3573012203950001","id":123}"#).unwrap();
            let redacted_ptr = pii_vault_redact_json(v1, json_input.as_ptr());
            assert!(!redacted_ptr.is_null());

            let redacted_str = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            pii_string_free(redacted_ptr);
            assert!(redacted_str.contains("<PII:ID_NIK:"));
            assert!(redacted_str.contains(r#""id":123"#));

            // Separate vault with same key rehydrates
            let v2 = pii_vault_new_with_key(0, key.as_ptr(), key.len());
            let to_rehydrate = CString::new(redacted_str).unwrap();
            let rehydrated_ptr = pii_vault_rehydrate(v2, to_rehydrate.as_ptr());
            assert!(!rehydrated_ptr.is_null());

            let rehydrated_str = CStr::from_ptr(rehydrated_ptr).to_str().unwrap().to_string();
            pii_string_free(rehydrated_ptr);
            assert!(rehydrated_str.contains("3573012203950001"));

            pii_vault_free(v1);
            pii_vault_free(v2);
        }
    }

    #[test]
    fn test_ffi_compact_hash_and_sealed_entries() {
        unsafe {
            let key = [44u8; 32];
            let v1 = pii_vault_new_with_key(0, key.as_ptr(), key.len());
            pii_vault_set_token_format(v1, 1); // CompactHash

            let input = CString::new("NIK 3573012203950001").unwrap();
            let redacted_ptr = pii_vault_redact(v1, input.as_ptr());
            let redacted_str = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            pii_string_free(redacted_ptr);
            assert!(redacted_str.contains("<ID_NIK_"));

            // Drain dirty entries
            let aad = CString::new("session:test_order").unwrap();
            let dirty_ptr = pii_vault_drain_dirty_sealed_entries_json(v1, aad.as_ptr());
            assert!(!dirty_ptr.is_null());
            let dirty_str = CStr::from_ptr(dirty_ptr).to_str().unwrap().to_string();
            pii_string_free(dirty_ptr);
            assert!(dirty_str.contains("PIIE1:"));

            // Second vault imports the dirty entries
            let v2 = pii_vault_new_with_key(0, key.as_ptr(), key.len());
            let json_map_c = CString::new(dirty_str).unwrap();
            let import_ok =
                pii_vault_import_sealed_entries_json(v2, json_map_c.as_ptr(), aad.as_ptr());
            assert!(import_ok);

            let to_rehydrate = CString::new(redacted_str).unwrap();
            let rehydrated_ptr = pii_vault_rehydrate(v2, to_rehydrate.as_ptr());
            let rehydrated_str = CStr::from_ptr(rehydrated_ptr).to_str().unwrap().to_string();
            pii_string_free(rehydrated_ptr);
            assert_eq!(rehydrated_str, "NIK 3573012203950001");

            pii_vault_free(v1);
            pii_vault_free(v2);
        }
    }

    #[test]
    fn test_ffi_invalid_locale_fails_closed() {
        unsafe {
            let bad = CString::new("global_typo").unwrap();
            let v = pii_vault_new_with_locales(bad.as_ptr());
            assert!(v.is_null(), "unknown locale must not produce a vault");

            let non_utf8 = CString::new(vec![0xff, 0xfe, b'g']).unwrap();
            let v = pii_vault_new_with_locales(non_utf8.as_ptr());
            assert!(v.is_null(), "non-UTF-8 locale CSV must fail closed");
        }
    }

    const CUSTOM_TOML: &str = r#"
locale = "custom"
name = "Custom"

[[rules]]
id = "CUSTOM_ACC"
tag_prefix = "CUSTOM_ACC"
regex = '\bACC-[0-9]{6}\b'
validator = "none"
"#;

    #[test]
    fn test_ffi_custom_toml_redacts_and_rehydrates() {
        unsafe {
            let key = [91u8; 32];
            let locales = CString::new("global").unwrap();
            let toml = CString::new(CUSTOM_TOML).unwrap();
            let vault = pii_vault_with_custom_toml(
                locales.as_ptr(),
                toml.as_ptr(),
                key.as_ptr(),
                key.len(),
            );
            assert!(!vault.is_null());

            let input = CString::new("Account ACC-123456 opened").unwrap();
            let redacted_ptr = pii_vault_redact(vault, input.as_ptr());
            assert!(!redacted_ptr.is_null());
            let redacted = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            pii_string_free(redacted_ptr);
            assert!(redacted.contains("<CUSTOM_ACC_"), "got: {}", redacted);

            // Rehydrate round-trips the custom token.
            let token_payload = CString::new(redacted).unwrap();
            let rehydrated_ptr = pii_vault_rehydrate(vault, token_payload.as_ptr());
            assert!(!rehydrated_ptr.is_null());
            let rehydrated = CStr::from_ptr(rehydrated_ptr).to_str().unwrap().to_string();
            pii_string_free(rehydrated_ptr);
            assert_eq!(rehydrated, "Account ACC-123456 opened");

            pii_vault_free(vault);
        }
    }

    #[test]
    fn test_ffi_custom_toml_null_key_generates_csprng_key() {
        unsafe {
            let toml = CString::new(CUSTOM_TOML).unwrap();
            let vault = pii_vault_with_custom_toml(ptr::null(), toml.as_ptr(), ptr::null(), 0);
            assert!(!vault.is_null());
            // A CSPRNG-keyed vault can still redact and rehydrate itself.
            let input = CString::new("Account ACC-123456 opened").unwrap();
            let redacted_ptr = pii_vault_redact(vault, input.as_ptr());
            assert!(!redacted_ptr.is_null());
            let redacted = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            pii_string_free(redacted_ptr);
            let token_payload = CString::new(redacted).unwrap();
            let rehydrated_ptr = pii_vault_rehydrate(vault, token_payload.as_ptr());
            assert!(!rehydrated_ptr.is_null());
            let rehydrated = CStr::from_ptr(rehydrated_ptr).to_str().unwrap().to_string();
            pii_string_free(rehydrated_ptr);
            assert_eq!(rehydrated, "Account ACC-123456 opened");
            pii_vault_free(vault);
        }
    }

    #[test]
    fn test_ffi_custom_toml_rejects_bad_key_len() {
        unsafe {
            let toml = CString::new(CUSTOM_TOML).unwrap();
            let key = [1u8; 32];
            // Non-null pointer with the wrong length is rejected.
            assert!(
                pii_vault_with_custom_toml(ptr::null(), toml.as_ptr(), key.as_ptr(), 16).is_null()
            );
            // Null pointer with a non-zero length is rejected too.
            assert!(
                pii_vault_with_custom_toml(ptr::null(), toml.as_ptr(), ptr::null(), 32).is_null()
            );
        }
    }

    #[test]
    fn test_ffi_custom_toml_rejects_invalid_toml() {
        unsafe {
            let bad_toml = CString::new(
                r#"
locale = "custom"
name = "Custom"

[[rules]]
id = "BAD"
tag_prefix = "BAD"
regex = '(unbalanced['
"#,
            )
            .unwrap();
            let v = pii_vault_with_custom_toml(ptr::null(), bad_toml.as_ptr(), ptr::null(), 0);
            assert!(v.is_null(), "invalid regex must fail closed");
        }
    }

    #[test]
    fn test_ffi_rehydrate_for_tool_ex_reports_blocked_token() {
        unsafe {
            let vault = pii_vault_new();
            assert!(!vault.is_null());

            // First redact so the vault knows the PII value.
            let input = CString::new("NIK 3573012203950001").unwrap();
            let redacted_ptr = pii_vault_redact(vault, input.as_ptr());
            assert!(!redacted_ptr.is_null());
            let redacted = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            pii_string_free(redacted_ptr);
            let token = {
                let start = redacted.find("<ID_NIK_").unwrap();
                let end = redacted.find('>').unwrap();
                redacted[start..=end].to_string()
            };

            // Untrusted tool must be blocked, and the offending token must be
            // surfaced through err_out.
            let mut err_out: *mut c_char = ptr::null_mut();
            let payload = CString::new(redacted).unwrap();
            let result =
                pii_vault_rehydrate_for_tool_ex(vault, payload.as_ptr(), false, &mut err_out);
            assert!(result.is_null());
            assert!(!err_out.is_null(), "blocked token must be reported");
            let reported = CStr::from_ptr(err_out).to_str().unwrap().to_string();
            pii_string_free(err_out);
            assert_eq!(reported, token, "got: {}", reported);

            // Trusted path still succeeds and does not touch err_out.
            let trusted =
                pii_vault_rehydrate_for_tool_ex(vault, payload.as_ptr(), true, &mut err_out);
            assert!(!trusted.is_null());
            assert!(err_out.is_null());
            pii_string_free(trusted);

            // Legacy entry point remains null-returning on block (ABI compat).
            let legacy = pii_vault_rehydrate_for_tool(vault, payload.as_ptr(), false);
            assert!(legacy.is_null());

            pii_vault_free(vault);
        }
    }

    #[test]
    fn test_ffi_error_variant_display_covers_blocked() {
        // Sanity: the extended constructor depends on ExfiltrationBlocked
        // carrying the token string.
        let err = SecurityError::ExfiltrationBlocked {
            token: "<ID_NIK_1>".to_string(),
        };
        assert!(err.to_string().contains("<ID_NIK_1>"));
    }

    #[test]
    fn test_ffi_empty_locale_csv_fails_closed() {
        unsafe {
            let empty = CString::new("").unwrap();
            assert!(pii_vault_new_with_locales(empty.as_ptr()).is_null());

            let blank = CString::new(" , ").unwrap();
            assert!(pii_vault_new_with_locales(blank.as_ptr()).is_null());

            let gap = CString::new("global,,id").unwrap();
            assert!(pii_vault_new_with_locales(gap.as_ptr()).is_null());

            // NULL still selects the default set.
            assert!(!pii_vault_new_with_locales(ptr::null()).is_null());
        }
    }

    #[test]
    fn test_ffi_custom_toml_rejects_empty_and_rule_less_toml() {
        unsafe {
            let empty_toml = CString::new("").unwrap();
            let blank_toml = CString::new("   \n  ").unwrap();
            let rule_less_toml = CString::new(r#"locale = "custom" name = "NoRules""#).unwrap();
            for toml in [
                empty_toml.as_ref(),
                blank_toml.as_ref(),
                rule_less_toml.as_ref(),
            ] {
                assert!(
                    pii_vault_with_custom_toml(ptr::null(), toml.as_ptr(), ptr::null(), 0)
                        .is_null(),
                    "empty/whitespace/rule-less TOML must fail closed"
                );
            }
        }
    }

    #[test]
    fn test_ffi_bad_policy_id_fails_closed() {
        unsafe {
            let key = [5u8; 32];
            assert!(pii_vault_new_with_key(2, key.as_ptr(), key.len()).is_null());
            assert!(pii_vault_new_with_key(255, key.as_ptr(), key.len()).is_null());
            assert!(!pii_vault_new_with_key(0, key.as_ptr(), key.len()).is_null());
            assert!(!pii_vault_new_with_key(1, key.as_ptr(), key.len()).is_null());
        }
    }

    #[test]
    fn test_ffi_invalid_format_id_does_not_reset() {
        unsafe {
            let vault = pii_vault_new();
            assert!(!vault.is_null());
            // Put the vault into stateless mode with valid id 2.
            pii_vault_set_token_format(vault, 2);
            assert!(pii_vault_is_stateless_mode(vault));
            // An invalid format id must not silently reset to Sequential.
            pii_vault_set_token_format(vault, 7);
            assert!(pii_vault_is_stateless_mode(vault));
            pii_vault_free(vault);
        }
    }

    #[test]
    fn test_ffi_seal_dirty_is_read_only_and_roundtrips() {
        unsafe {
            let key = [63u8; 32];
            let v1 = pii_vault_new_with_key(0, key.as_ptr(), key.len());
            pii_vault_set_token_format(v1, 1); // CompactHash: tokens go to the dirty set.
            let input = CString::new("NIK 3573012203950001").unwrap();
            let red_ptr = pii_vault_redact(v1, input.as_ptr());
            assert!(!red_ptr.is_null());
            pii_string_free(red_ptr);

            // seal_* takes a read-only handle and yields the dirty entries.
            let aad = CString::new("aad:a").unwrap();
            let sealed_ptr = pii_vault_seal_dirty_sealed_entries_json(v1, aad.as_ptr());
            assert!(!sealed_ptr.is_null());
            let sealed = CStr::from_ptr(sealed_ptr).to_str().unwrap().to_string();
            pii_string_free(sealed_ptr);
            assert!(sealed.contains("PIIE1:"));

            // is_stateless_mode toggles.
            pii_vault_set_stateless_mode(v1, true);
            assert!(pii_vault_is_stateless_mode(v1));
            pii_vault_set_stateless_mode(v1, false);
            assert!(!pii_vault_is_stateless_mode(v1));

            // clear_dirty_tokens via JSON list.
            let tokens_json = CString::new(r#"["whatever"]"#).unwrap();
            assert!(pii_vault_clear_dirty_tokens(v1, tokens_json.as_ptr()));
            assert!(!pii_vault_clear_dirty_tokens(v1, ptr::null()));

            pii_vault_free(v1);
        }
    }
}
