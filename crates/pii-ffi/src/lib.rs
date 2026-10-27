#![allow(clippy::missing_safety_doc)]

use pii_core::{PiiCatalog, PiiSessionVault, SecurityPolicy, StreamingRehydrator, ToolTrustLevel};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;

/// Opaque thread-safe vault handle.
pub struct PiiVaultHandle(pub Mutex<PiiSessionVault>);

/// Opaque streaming rehydrator handle.
pub struct PiiStreamHandle(pub Mutex<StreamingRehydrator>);

#[no_mangle]
pub extern "C" fn pii_vault_new() -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        let vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        Box::into_raw(Box::new(PiiVaultHandle(Mutex::new(vault))))
    }))
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_new_with_locales(locales: *const c_char) -> *mut PiiVaultHandle {
    catch_unwind(AssertUnwindSafe(|| {
        if locales.is_null() {
            return pii_vault_new();
        }
        let loc_str = match CStr::from_ptr(locales).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let loc_vec: Vec<&str> = loc_str.split(',').map(|s| s.trim()).collect();
        let catalog = PiiCatalog::with_locales(&loc_vec).unwrap_or_default();
        let vault = PiiSessionVault::from_catalog(catalog);
        Box::into_raw(Box::new(PiiVaultHandle(Mutex::new(vault))))
    }))
    .unwrap_or(ptr::null_mut())
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
        let mut vault = match handle.0.lock() {
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
        let vault = match handle.0.lock() {
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
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || payload.is_null() {
            return ptr::null_mut();
        }
        let c_str = match CStr::from_ptr(payload).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };
        let handle = &*ptr;
        let vault = match handle.0.lock() {
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
            Err(_) => ptr::null_mut(), // Blocked
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
        let vault = match vault_handle.0.lock() {
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
        let vault = match vault_handle.0.lock() {
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
