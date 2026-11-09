"""High-level Python API over the pii-ffi C-ABI.

Every method follows the zero-leak pattern: string-returning FFI calls are
declared with ``c_void_p`` restype, read via ``ctypes.string_at`` and freed
immediately on the Rust heap.

Lifecycle is thread-safe: ``close()`` frees the native handle under the
instance lock, and every call re-validates the handle before touching FFI so
a closed vault can never be double-freed or used after free.
"""
from __future__ import annotations

import ctypes
import threading
from enum import IntEnum
from typing import Optional

from pii_shield._ffi import get_lib, read_and_free

_VOID_P = ctypes.c_void_p


class TokenFormat(IntEnum):
    Sequential = 0
    CompactHash = 1
    StatelessSealed = 2


class ToolTrustLevel(IntEnum):
    InternalTrusted = 0
    ExternalUntrusted = 1


class ExfiltrationBlockedError(Exception):
    """Raised when an untrusted tool attempts to rehydrate PII tokens.

    ``token`` is the exact offending vault token (e.g. ``<ID_NIK_A1GW86>``)
    reported by ``pii_vault_rehydrate_for_tool_ex``.
    """

    def __init__(self, token: str) -> None:
        self.token = token
        super().__init__(f"PII exfiltration blocked: {token}")


def _encode_cstr(value: str, name: str) -> bytes:
    """Encode a Python string as a NUL-terminated C input.

    Interior NUL bytes would silently truncate the argument at the native
    boundary, so they are rejected up front.
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain interior NUL bytes")
    return value.encode("utf-8")


def _requires_bytes(
    value: Optional[bytes], name: str, expected_len: Optional[int] = None
) -> Optional[bytes]:
    if value is None:
        return None
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like, got {type(value).__name__}")
    if expected_len is not None and len(value) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes")
    return bytes(value)


class PiiSessionVault:
    """Python wrapper over ``PiiVaultHandle``."""

    def __init__(
        self,
        *,
        locales_csv: Optional[str] = None,
        custom_toml: Optional[str] = None,
        key: Optional[bytes] = None,
    ) -> None:
        """Create a vault.

        All constructors fail closed: invalid locales, invalid custom TOML or
        a malformed key raise ``ValueError`` instead of silently producing a
        0-rule vault.

        :param locales_csv: comma-separated locales, e.g. ``"global,id,us"``.
            ``None`` selects the default ``"global,id"``; an empty string
            fails closed.
        :param custom_toml: extra TOML rule catalog merged on top.
        :param key: 32-byte shared key for cross-vault rehydration; ``None``
            generates a CSPRNG key (vault-local only).
        """
        lib = get_lib()
        self._lib = lib
        self._lock = threading.RLock()
        self._handle: Optional[int] = None

        key = _requires_bytes(key, "key", expected_len=32)

        if custom_toml is not None:
            key_buf = ctypes.create_string_buffer(key) if key is not None else None
            key_len = len(key) if key is not None else 0
            ptr = lib.cdll.pii_vault_with_custom_toml(
                _encode_cstr(locales_csv, "locales_csv") if locales_csv is not None else None,
                _encode_cstr(custom_toml, "custom_toml"),
                key_buf if key_buf is not None else None,
                key_len,
            )
        elif key is not None:
            ptr = lib.cdll.pii_vault_new_with_locales_and_key(
                _encode_cstr(locales_csv, "locales_csv") if locales_csv is not None else None,
                ctypes.create_string_buffer(key),
                len(key),
            )
        else:
            ptr = lib.cdll.pii_vault_new_with_locales(
                _encode_cstr(locales_csv, "locales_csv") if locales_csv is not None else None
            )
        if not ptr:
            raise ValueError(
                "Vault construction failed (invalid locales, TOML rules, or key). "
                "The library fails closed for an invalid configuration."
            )
        self._handle = ptr

    # -- lifecycle --------------------------------------------------------------
    def _require_handle(self) -> int:
        self._lock.acquire()
        try:
            if self._handle is None:
                raise ValueError("PiiSessionVault is closed")
            return self._handle
        finally:
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
        if handle:
            self._lib.cdll.pii_vault_free(handle)

    def __enter__(self) -> "PiiSessionVault":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # -- configuration (write-locked) --------------------------------------------
    def set_token_format(self, fmt: TokenFormat) -> None:
        if isinstance(fmt, bool) or not isinstance(fmt, TokenFormat):
            fmt = TokenFormat(fmt)
        handle = self._require_handle()
        self._lib.cdll.pii_vault_set_token_format(handle, int(fmt))

    def set_stateless_mode(self, enabled: bool) -> None:
        handle = self._require_handle()
        self._lib.cdll.pii_vault_set_stateless_mode(handle, bool(enabled))

    def is_stateless_mode(self) -> bool:
        """Whether the vault is currently in stateless sealed-token mode."""
        handle = self._require_handle()
        return bool(self._lib.cdll.pii_vault_is_stateless_mode(handle))

    # -- redaction (write-locked) -------------------------------------------------
    def redact(self, text: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_redact(handle, _encode_cstr(text, "text"))
        if not ptr:
            raise RuntimeError("pii-shield native call failed in redact")
        return read_and_free(self._lib, ptr) or ""

    def redact_json(self, payload: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_redact_json(
            handle, _encode_cstr(payload, "payload")
        )
        if not ptr:
            raise RuntimeError("pii-shield native call failed in redact_json")
        return read_and_free(self._lib, ptr) or ""

    # -- rehydration (read-locked) -------------------------------------------------
    def rehydrate(self, text: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_rehydrate(handle, _encode_cstr(text, "text"))
        if not ptr:
            raise RuntimeError("pii-shield native call failed in rehydrate")
        return read_and_free(self._lib, ptr) or ""

    def rehydrate_for_tool(self, payload: str, trusted: ToolTrustLevel | bool) -> str:
        """Rehydrate for a tool call, raising ``ExfiltrationBlockedError`` when
        the payload is heading to an untrusted consumer.

        :param trusted: a ``ToolTrustLevel`` (only ``InternalTrusted`` passes
            the ACL) or a plain ``bool``. Note that bare ``1 == True`` and
            enum comparison would otherwise misroute
            ``ToolTrustLevel.ExternalUntrusted`` to the trusted path, which
            is why mapping is done on identity first.
        """
        if isinstance(trusted, bool):
            is_trusted = trusted
        elif isinstance(trusted, ToolTrustLevel):
            is_trusted = trusted is ToolTrustLevel.InternalTrusted
        else:
            raise TypeError(
                f"trusted must be a ToolTrustLevel or bool, got {type(trusted).__name__}"
            )
        handle = self._require_handle()
        err_ptr = _VOID_P(0)
        ptr = self._lib.cdll.pii_vault_rehydrate_for_tool_ex(
            handle, _encode_cstr(payload, "payload"), is_trusted, ctypes.byref(err_ptr)
        )
        if not ptr:
            if err_ptr.value is not None:
                token = read_and_free(self._lib, err_ptr.value)
                if token is not None:
                    raise ExfiltrationBlockedError(token)
            raise RuntimeError("pii_vault_rehydrate_for_tool_ex failed")
        return read_and_free(self._lib, ptr) or ""

    # -- persistence -----------------------------------------------------------------
    def export_sealed_entries_json(self, aad: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_export_sealed_entries_json(
            handle, _encode_cstr(aad, "aad")
        )
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError("pii-shield native call failed in export_sealed_entries_json")
        return out

    def drain_dirty_sealed_entries_json(self, aad: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_drain_dirty_sealed_entries_json(
            handle, _encode_cstr(aad, "aad")
        )
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError(
                "pii-shield native call failed in drain_dirty_sealed_entries_json"
            )
        return out

    def seal_dirty_sealed_entries_json(self, aad: str) -> str:
        """Two-phase sync, step 1: snapshot the dirty set without clearing it."""
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_seal_dirty_sealed_entries_json(
            handle, _encode_cstr(aad, "aad")
        )
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError(
                "pii-shield native call failed in seal_dirty_sealed_entries_json"
            )
        return out

    def clear_dirty_tokens(self, tokens: "list[str] | str") -> None:
        """Two-phase sync, step 2: clear the dirty tokens after a successful
        store write. Accepts a JSON string of an array of tokens, or a Python
        list of tokens (serialized for you)."""
        if not isinstance(tokens, str):
            import json

            tokens = json.dumps(list(tokens))
        handle = self._require_handle()
        ok = self._lib.cdll.pii_vault_clear_dirty_tokens(
            handle, _encode_cstr(tokens, "tokens")
        )
        if not ok:
            raise ValueError("Failed to clear dirty tokens (invalid JSON token array)")

    def import_sealed_entries_json(self, json_map: str, aad: str) -> None:
        handle = self._require_handle()
        ok = self._lib.cdll.pii_vault_import_sealed_entries_json(
            handle,
            _encode_cstr(json_map, "json_map"),
            _encode_cstr(aad, "aad"),
        )
        if not ok:
            raise ValueError("Failed to import sealed entries (corrupt JSON map or AAD mismatch)")

    def export_sealed_state(self, aad: str) -> str:
        handle = self._require_handle()
        ptr = self._lib.cdll.pii_vault_export_sealed_state(handle, _encode_cstr(aad, "aad"))
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError("pii-shield native call failed in export_sealed_state")
        return out

    def import_sealed_state(self, sealed: str, aad: str) -> None:
        handle = self._require_handle()
        ok = self._lib.cdll.pii_vault_import_sealed_state(
            handle, _encode_cstr(sealed, "sealed"), _encode_cstr(aad, "aad")
        )
        if not ok:
            raise ValueError("Failed to import sealed state (corrupt blob or AAD mismatch)")


class StreamingRehydrator:
    """Wrapper over ``PiiStreamHandle``: rehydrates tokens split across SSE chunks."""

    def __init__(self) -> None:
        lib = get_lib()
        self._lib = lib
        self._lock = threading.RLock()
        self._handle = lib.cdll.pii_stream_new()
        if not self._handle:
            raise RuntimeError("Failed to allocate PiiStreamHandle")

    def close(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
        if handle:
            self._lib.cdll.pii_stream_free(handle)

    def __enter__(self) -> "StreamingRehydrator":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _require_handles(
        self, vault: PiiSessionVault
    ) -> "tuple[int, int]":
        with self._lock:
            if self._handle is None:
                raise ValueError("StreamingRehydrator is closed")
            stream_handle = self._handle
        vault_handle = vault._require_handle()
        return stream_handle, vault_handle

    def push_chunk(self, chunk: str, vault: PiiSessionVault) -> str:
        stream_handle, vault_handle = self._require_handles(vault)
        ptr = self._lib.cdll.pii_stream_push_chunk(
            stream_handle, vault_handle, _encode_cstr(chunk, "chunk")
        )
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError("pii-shield native call failed in push_chunk")
        return out

    def flush(self, vault: PiiSessionVault) -> str:
        stream_handle, vault_handle = self._require_handles(vault)
        ptr = self._lib.cdll.pii_stream_flush(stream_handle, vault_handle)
        out = read_and_free(self._lib, ptr)
        if out is None:
            raise RuntimeError("pii-shield native call failed in flush")
        return out
