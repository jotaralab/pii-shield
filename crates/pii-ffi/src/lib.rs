use pii_core::{PiiSessionVault, SecurityPolicy};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

#[no_mangle]
pub extern "C" fn pii_vault_new() -> *mut PiiSessionVault {
    Box::into_raw(Box::new(PiiSessionVault::new(
        SecurityPolicy::IndonesiaUuPdpStrict,
    )))
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_free(ptr: *mut PiiSessionVault) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pii_vault_redact(
    ptr: *mut PiiSessionVault,
    input: *const c_char,
) -> *mut c_char {
    if ptr.is_null() || input.is_null() {
        return ptr::null_mut();
    }
    let vault = &mut *ptr;
    let c_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let redacted = vault.redact(c_str);
    CString::new(redacted).unwrap_or_default().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn pii_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
