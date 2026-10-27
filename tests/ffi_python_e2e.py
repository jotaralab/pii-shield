#!/usr/bin/env python3
import ctypes
import json
import os
import sys

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

def main():
    lib_path = find_lib()
    print(f"[Python FFI E2E] Loading shared library from {lib_path}")
    lib = ctypes.CDLL(lib_path)

    # Function signatures
    lib.pii_vault_new_with_locales.argtypes = [ctypes.c_char_p]
    lib.pii_vault_new_with_locales.restype = ctypes.c_void_p

    lib.pii_vault_new_with_key.argtypes = [ctypes.c_uint8, ctypes.c_char_p, ctypes.c_size_t]
    lib.pii_vault_new_with_key.restype = ctypes.c_void_p

    lib.pii_vault_set_token_format.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
    lib.pii_vault_set_token_format.restype = None

    lib.pii_vault_redact.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pii_vault_redact.restype = ctypes.c_char_p

    lib.pii_vault_redact_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pii_vault_redact_json.restype = ctypes.c_char_p

    lib.pii_vault_rehydrate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pii_vault_rehydrate.restype = ctypes.c_char_p

    lib.pii_vault_rehydrate_for_tool.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
    lib.pii_vault_rehydrate_for_tool.restype = ctypes.c_char_p

    lib.pii_vault_drain_dirty_sealed_entries_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pii_vault_drain_dirty_sealed_entries_json.restype = ctypes.c_char_p

    lib.pii_vault_import_sealed_entries_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.pii_vault_import_sealed_entries_json.restype = ctypes.c_bool

    lib.pii_vault_free.argtypes = [ctypes.c_void_p]
    lib.pii_vault_free.restype = None

    lib.pii_string_free.argtypes = [ctypes.c_char_p]
    lib.pii_string_free.restype = None

    # 1. Initialize Vault 1 with cluster key
    cluster_key = b"12345678901234567890123456789012"
    v1 = lib.pii_vault_new_with_key(0, cluster_key, len(cluster_key))
    assert v1 is not None, "Vault 1 creation failed"
    lib.pii_vault_set_token_format(v1, 1) # CompactHash

    # 2. Redact text
    raw_prompt = b"Check customer NIK 3573012203950001 and email test@jotaralab.com"
    masked_c = lib.pii_vault_redact(v1, raw_prompt)
    masked_py = masked_c.decode("utf-8")
    print(f"[Python FFI E2E] Redacted output: {masked_py}")
    assert "<ID_NIK_" in masked_py
    assert "<EMAIL_" in masked_py
    assert "3573012203950001" not in masked_py

    # 3. Drain dirty entries to JSON
    aad = b"session:python_turn_1"
    dirty_json_c = lib.pii_vault_drain_dirty_sealed_entries_json(v1, aad)
    dirty_json_py = dirty_json_c.decode("utf-8")
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
    rehydrated_c = lib.pii_vault_rehydrate(v2, masked_c)
    rehydrated_py = rehydrated_c.decode("utf-8")
    print(f"[Python FFI E2E] Rehydrated output: {rehydrated_py}")
    assert rehydrated_py == raw_prompt.decode("utf-8")

    # 6. Test JSON safe redaction
    json_in = b'{"nik":"3573012203950001","order_id":1234567890123456}'
    json_masked_c = lib.pii_vault_redact_json(v1, json_in)
    json_masked_py = json_masked_c.decode("utf-8")
    parsed = json.loads(json_masked_py)
    assert parsed["order_id"] == 1234567890123456
    assert parsed["nik"].startswith("<ID_NIK_")

    # 7. Cleanup memory cleanly
    lib.pii_vault_free(v1)
    lib.pii_vault_free(v2)
    print("[Python FFI E2E] All foreign-language C-ABI tests passed successfully!")

if __name__ == "__main__":
    main()
