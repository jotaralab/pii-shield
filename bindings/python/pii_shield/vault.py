"""High-level Python API over the pii-ffi C-ABI.

Every method follows the zero-leak pattern: string-returning FFI calls are
declared with ``c_void_p`` restype, read via ``ctypes.string_at`` and freed
immediately on the Rust heap.
"""
from __future__ import annotations

import ctypes
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
        :param custom_toml: extra TOML rule catalog merged on top.
        :param key: 32-byte shared key for cross-vault rehydration; ``None``
            generates a CSPRNG key (vault-local only).
        """
        lib = get_lib()
        self._lib = lib
        if custom_toml is not None:
            key_buf = ctypes.create_string_buffer(bytes(key)) if key is not None else None
            key_len = len(key) if key is not None else 0
            ptr = lib.cdll.pii_vault_with_custom_toml(
                locales_csv.encode("utf-8") if locales_csv is not None else None,
                custom_toml.encode("utf-8"),
                key_buf if key_buf is not None else None,
                key_len,
            )
        elif key is not None:
            if len(key) != 32:
                raise ValueError("key must be exactly 32 bytes")
            ptr = lib.cdll.pii_vault_new_with_locales_and_key(
                locales_csv.encode("utf-8") if locales_csv is not None else None,
                ctypes.create_string_buffer(bytes(key)),
                len(key),
            )
        else:
            ptr = lib.cdll.pii_vault_new_with_locales(
                locales_csv.encode("utf-8") if locales_csv is not None else None
            )
        if not ptr:
            raise ValueError(
                "Vault construction failed (invalid locales, TOML rules, or key). "
                "The library fails closed for an invalid configuration."
            )
        self._handle = ptr

    # -- lifecycle --------------------------------------------------------------
    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.cdll.pii_vault_free(self._handle)
            self._handle = None

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
        self._lib.cdll.pii_vault_set_token_format(self._handle, int(fmt))

    def set_stateless_mode(self, enabled: bool) -> None:
        self._lib.cdll.pii_vault_set_stateless_mode(self._handle, bool(enabled))

    # -- redaction (write-locked) -------------------------------------------------
    def redact(self, text: str) -> str:
        ptr = self._lib.cdll.pii_vault_redact(self._handle, text.encode("utf-8"))
        return read_and_free(self._lib, ptr) or ""

    def redact_json(self, payload: str) -> str:
        ptr = self._lib.cdll.pii_vault_redact_json(self._handle, payload.encode("utf-8"))
        return read_and_free(self._lib, ptr) or ""

    # -- rehydration (read-locked) -------------------------------------------------
    def rehydrate(self, text: str) -> str:
        ptr = self._lib.cdll.pii_vault_rehydrate(self._handle, text.encode("utf-8"))
        return read_and_free(self._lib, ptr) or ""

    def rehydrate_for_tool(self, payload: str, trusted: ToolTrustLevel | bool) -> str:
        """Rehydrate for a tool call, raising ``ExfiltrationBlockedError`` when
        the payload is heading to an untrusted consumer."""
        is_trusted = bool(trusted is True or trusted == ToolTrustLevel.InternalTrusted)
        err_ptr = _VOID_P(0)
        ptr = self._lib.cdll.pii_vault_rehydrate_for_tool_ex(
            self._handle, payload.encode("utf-8"), is_trusted, ctypes.byref(err_ptr)
        )
        if not ptr:
            token = read_and_free(self._lib, err_ptr)
            raise ExfiltrationBlockedError(token or "<UNKNOWN>")
        return read_and_free(self._lib, ptr) or ""

    # -- persistence -----------------------------------------------------------------
    def export_sealed_entries_json(self, aad: str) -> str:
        ptr = self._lib.cdll.pii_vault_export_sealed_entries_json(
            self._handle, aad.encode("utf-8")
        )
        return read_and_free(self._lib, ptr) or ""

    def drain_dirty_sealed_entries_json(self, aad: str) -> str:
        ptr = self._lib.cdll.pii_vault_drain_dirty_sealed_entries_json(
            self._handle, aad.encode("utf-8")
        )
        return read_and_free(self._lib, ptr) or ""

    def import_sealed_entries_json(self, json_map: str, aad: str) -> None:
        ok = self._lib.cdll.pii_vault_import_sealed_entries_json(
            self._handle, json_map.encode("utf-8"), aad.encode("utf-8")
        )
        if not ok:
            raise ValueError("Failed to import sealed entries (corrupt JSON map or AAD mismatch)")

    def export_sealed_state(self, aad: str) -> str:
        ptr = self._lib.cdll.pii_vault_export_sealed_state(self._handle, aad.encode("utf-8"))
        return read_and_free(self._lib, ptr) or ""

    def import_sealed_state(self, sealed: str, aad: str) -> None:
        ok = self._lib.cdll.pii_vault_import_sealed_state(
            self._handle, sealed.encode("utf-8"), aad.encode("utf-8")
        )
        if not ok:
            raise ValueError("Failed to import sealed state (corrupt blob or AAD mismatch)")


class StreamingRehydrator:
    """Wrapper over ``PiiStreamHandle``: rehydrates tokens split across SSE chunks."""

    def __init__(self) -> None:
        lib = get_lib()
        self._lib = lib
        self._handle = lib.cdll.pii_stream_new()

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.cdll.pii_stream_free(self._handle)
            self._handle = None

    def __enter__(self) -> "StreamingRehydrator":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def push_chunk(self, chunk: str, vault: PiiSessionVault) -> str:
        ptr = self._lib.cdll.pii_stream_push_chunk(
            self._handle, vault._handle, chunk.encode("utf-8")
        )
        return read_and_free(self._lib, ptr) or ""

    def flush(self, vault: PiiSessionVault) -> str:
        ptr = self._lib.cdll.pii_stream_flush(self._handle, vault._handle)
        return read_and_free(self._lib, ptr) or ""
