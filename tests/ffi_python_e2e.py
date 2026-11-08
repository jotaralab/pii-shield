#!/usr/bin/env python3
"""E2E test of the pii-ffi C-ABI from Python via ctypes.

Memory-safety invariant: every function that returns `*mut c_char` must be
declared with `restype = ctypes.c_void_p` so ctypes does NOT copy the C
string into a Python `bytes` object and discard the raw pointer — which
would make it impossible to call `pii_string_free` and leak the Rust heap
allocation. Strings are read via `ctypes.string_at(ptr)` and the raw
pointer is always handed back to `pii_string_free` immediately.
"""
import ctypes
import json
import os

def find_lib():
    candidates = [
        "target/debug/libpii_ffi.so",
        "target/release/libpii_ffi.so",
        "../../target/debug/libpii_ffi.so",
        "../../target/release/libpii_ffi.so",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    raise FileNotFoundError("Could not find libpii_ffi.so. Build with `cargo build -p pii-ffi` first.")

VOID_P = ctypes.c_void_p

def read_string(lib, ptr):
    """Read a *mut c_char result as Python str and free the Rust heap buffer."""
    if not ptr:
        return None
    try:
        return ctypes.string_at(ptr).decode("utf-8")
    finally:
        lib.pii_string_free(ptr)

def main():
    lib_path = os.environ.get("PII_SHIELD_LIB_PATH") or find_lib()
    print(f"[Python FFI E2E] Loading shared library from {lib_path}")
    lib = ctypes.CDLL(lib_path)

    # ---- Function signatures (zero-leak string lifecycle) ----
    lib.pii_vault_new_with_locales.argtypes = [ctypes.c_char_p]
    lib.pii_vault_new_with_locales.restype = VOID_P

    lib.pii_vault_new_with_key.argtypes = [ctypes.c_uint8, ctypes.c_char_p, ctypes.c_size_t]
    lib.pii_vault_new_with_key.restype = VOID_P

    lib.pii_vault_with_custom_toml.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.pii_vault_with_custom_toml.restype = VOID_P

    lib.pii_vault_set_token_format.argtypes = [VOID_P, ctypes.c_uint8]
    lib.pii_vault_set_token_format.restype = None

    lib.pii_vault_redact.argtypes = [VOID_P, ctypes.c_char_p]
    lib.pii_vault_redact.restype = VOID_P

    lib.pii_vault_redact_json.argtypes = [VOID_P, ctypes.c_char_p]
    lib.pii_vault_redact_json.restype = VOID_P

    lib.pii_vault_rehydrate.argtypes = [VOID_P, ctypes.c_char_p]
    lib.pii_vault_rehydrate.restype = VOID_P

    lib.pii_vault_rehydrate_for_tool_ex.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_bool, ctypes.POINTER(VOID_P)]
    lib.pii_vault_rehydrate_for_tool_ex.restype = VOID_P

    lib.pii_stream_new.argtypes = []
    lib.pii_stream_new.restype = VOID_P

    lib.pii_stream_push_chunk.argtypes = [VOID_P, VOID_P, ctypes.c_char_p]
    lib.pii_stream_push_chunk.restype = VOID_P

    lib.pii_stream_flush.argtypes = [VOID_P, VOID_P]
    lib.pii_stream_flush.restype = VOID_P

    lib.pii_stream_free.argtypes = [VOID_P]
    lib.pii_stream_free.restype = None

    lib.pii_vault_drain_dirty_sealed_entries_json.argtypes = [VOID_P, ctypes.c_char_p]
    lib.pii_vault_drain_dirty_sealed_entries_json.restype = VOID_P

    lib.pii_vault_import_sealed_entries_json.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_char_p]
    lib.pii_vault_import_sealed_entries_json.restype = ctypes.c_bool

    lib.pii_vault_free.argtypes = [VOID_P]
    lib.pii_vault_free.restype = None

    lib.pii_string_free.argtypes = [VOID_P]
    lib.pii_string_free.restype = None

    # 1. Initialize Vault 1 with cluster key
    cluster_key = b"12345678901234567890123456789012"
    v1 = lib.pii_vault_new_with_key(0, cluster_key, len(cluster_key))
    assert v1 is not None, "Vault 1 creation failed"
    lib.pii_vault_set_token_format(v1, 1) # CompactHash

    # 2. Redact text
    raw_prompt = "Check customer NIK 3573012203950001 and email test@jotaralab.com"
    masked_py = read_string(lib, lib.pii_vault_redact(v1, raw_prompt.encode("utf-8")))
    print(f"[Python FFI E2E] Redacted output: {masked_py}")
    assert "<ID_NIK_" in masked_py
    assert "<EMAIL_" in masked_py
    assert "3573012203950001" not in masked_py

    # 3. Drain dirty entries to JSON
    aad = b"session:python_turn_1"
    dirty_json_py = read_string(lib, lib.pii_vault_drain_dirty_sealed_entries_json(v1, aad))
    dirty_map = json.loads(dirty_json_py)
    print(f"[Python FFI E2E] Drained dirty map with {len(dirty_map)} entries")
    assert len(dirty_map) == 2
    for token, sealed in dirty_map.items():
        assert token.startswith("<")
        assert sealed.startswith("PIIE1:")

    # 4. Initialize Vault 2 on separate 'pod' with same key
    v2 = lib.pii_vault_new_with_key(0, cluster_key, len(cluster_key))
    assert v2 is not None

    # Import dirty entries into Vault 2
    import_ok = lib.pii_vault_import_sealed_entries_json(v2, dirty_json_py.encode("utf-8"), aad)
    assert import_ok, "Importing sealed entries into Vault 2 failed"

    # 5. Rehydrate in Vault 2
    rehydrated_py = read_string(lib, lib.pii_vault_rehydrate(v2, masked_py.encode("utf-8")))
    print(f"[Python FFI E2E] Rehydrated output: {rehydrated_py}")
    assert rehydrated_py == raw_prompt

    # 6. Test JSON safe redaction
    json_in = b'{"nik":"3573012203950001","order_id":1234567890123456}'
    json_masked_py = read_string(lib, lib.pii_vault_redact_json(v1, json_in))
    parsed = json.loads(json_masked_py)
    assert parsed["order_id"] == 1234567890123456
    assert parsed["nik"].startswith("<ID_NIK_")

    # 6b. Blocked exfiltration token is surfaced via the _ex variant
    err_ptr = ctypes.c_void_p()
    blocked_ptr = lib.pii_vault_rehydrate_for_tool_ex(
        v2, masked_py.encode("utf-8"), False, ctypes.byref(err_ptr)
    )
    assert blocked_ptr is None, "untrusted tool must be blocked"
    assert err_ptr.value is not None, "blocked token must be reported"
    blocked_token = read_string(lib, err_ptr)
    print(f"[Python FFI E2E] Exfiltration blocked token: {blocked_token}")
    assert blocked_token.startswith("<") and blocked_token.endswith(">"), blocked_token

    # 6c. Streaming rehydrator: feed the masked text split across chunks
    # (like SSE) and confirm tokens rehydrate to the original.
    stream_c = lib.pii_stream_new()
    assert stream_c is not None
    split = len(masked_py) // 2
    out_parts = []
    out_parts.append(read_string(lib, lib.pii_stream_push_chunk(stream_c, v1, masked_py[:split].encode("utf-8"))))
    out_parts.append(read_string(lib, lib.pii_stream_push_chunk(stream_c, v1, masked_py[split:].encode("utf-8"))))
    out_parts.append(read_string(lib, lib.pii_stream_flush(stream_c, v1)))
    streamed = "".join(p or "" for p in out_parts)
    assert streamed == raw_prompt, f"streamed rehydrate mismatch: {streamed!r}"
    lib.pii_stream_free(stream_c)
    print("[Python FFI E2E] Streaming rehydrator working")

    # 6d. Custom TOML rules
    custom_toml = (
        'locale = "custom"\n'
        'name = "Custom"\n\n'
        "[[rules]]\n"
        'id = "CUSTOM_ACC"\n'
        'tag_prefix = "CUSTOM_ACC"\n'
        "regex = '\\bACC-[0-9]{6}\\b'\n"
    )
    vc = lib.pii_vault_with_custom_toml(b"global", custom_toml.encode("utf-8"), None, 0)
    assert vc is not None, "custom TOML vault creation failed"
    acc_masked = read_string(lib, lib.pii_vault_redact(vc, b"Account ACC-123456 opened"))
    assert "<CUSTOM_ACC_" in acc_masked, acc_masked
    lib.pii_vault_free(vc)
    print("[Python FFI E2E] Custom TOML rules working")

    # 7. Cleanup memory cleanly
    lib.pii_vault_free(v1)
    lib.pii_vault_free(v2)
    print("[Python FFI E2E] All foreign-language C-ABI tests passed successfully with 0 leaked strings!")

if __name__ == "__main__":
    main()
