"""ctypes loader and C-ABI bindings for pii-shield.

Zero-leak string lifecycle: functions returning `*mut c_char` are declared
with ``restype = ctypes.c_void_p`` so ctypes keeps the raw pointer available
for ``pii_string_free``. Values are read with ``ctypes.string_at``.

Library discovery order (``_find_library``):

1. ``PII_SHIELD_LIB_PATH`` environment variable
2. workspace ``target/release`` then ``target/debug``
3. system loader default (bare lib name via ``ctypes.CDLL``)
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Callable, Optional

_VOID_P = ctypes.c_void_p


def _lib_filename() -> str:
    if os.name == "nt":
        return "pii_ffi.dll"
    if os.uname().sysname == "Darwin":  # macOS
        return "libpii_ffi.dylib"
    return "libpii_ffi.so"


def _find_library() -> str:
    """Resolve the path of the shared library, honoring PII_SHIELD_LIB_PATH."""
    filename = _lib_filename()
    env = os.environ.get("PII_SHIELD_LIB_PATH")
    if env:
        if os.path.exists(env):
            return env
        raise FileNotFoundError(
            f"PII_SHIELD_LIB_PATH is set to {env!r} but the file does not exist"
        )
    candidates: list[Path] = []
    for base in (os.environ.get("PII_SHIELD_WS"),
                 ".",
                 Path(os.path.dirname(__file__)).parent.parent / ".."):
        if not base:
            continue
        root = Path(base).resolve()
        for build in ("release", "debug"):
            candidates.append(root / "target" / build / filename)
    # Walk upward from this file so `pip install`ed editable sources still find it.
    here = Path(os.path.dirname(__file__)).resolve()
    for parent in here.parents:
        for build in ("release", "debug"):
            candidates.append(parent / "target" / build / filename)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    # Last resort: system loader (LD_LIBRARY_PATH / rpath) decides.
    return filename


class _Lib:
    """Lazy wrapper building the ctypes signatures exactly once."""

    def __init__(self) -> None:
        self.cdll: ctypes.CDLL = ctypes.CDLL(_find_library())
        self._bind()

    def _bind(self) -> None:
        lib = self.cdll
        v = _VOID_P

        # -- vault lifecycle ------------------------------------------------
        lib.pii_vault_new.argtypes = []
        lib.pii_vault_new.restype = v

        lib.pii_vault_new_with_locales.argtypes = [ctypes.c_char_p]
        lib.pii_vault_new_with_locales.restype = v

        lib.pii_vault_new_with_key.argtypes = [ctypes.c_uint8, ctypes.c_char_p, ctypes.c_size_t]
        lib.pii_vault_new_with_key.restype = v

        lib.pii_vault_new_with_locales_and_key.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.pii_vault_new_with_locales_and_key.restype = v

        lib.pii_vault_with_custom_toml.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.pii_vault_with_custom_toml.restype = v

        lib.pii_vault_free.argtypes = [v]
        lib.pii_vault_free.restype = None

        lib.pii_vault_set_token_format.argtypes = [v, ctypes.c_uint8]
        lib.pii_vault_set_token_format.restype = None

        lib.pii_vault_set_stateless_mode.argtypes = [v, ctypes.c_bool]
        lib.pii_vault_set_stateless_mode.restype = None

        # -- redaction / rehydration ----------------------------------------
        lib.pii_vault_redact.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_redact.restype = v

        lib.pii_vault_redact_json.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_redact_json.restype = v

        lib.pii_vault_rehydrate.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_rehydrate.restype = v

        lib.pii_vault_rehydrate_for_tool.argtypes = [v, ctypes.c_char_p, ctypes.c_bool]
        lib.pii_vault_rehydrate_for_tool.restype = v

        lib.pii_vault_rehydrate_for_tool_ex.argtypes = [
            v, ctypes.c_char_p, ctypes.c_bool, ctypes.POINTER(v)
        ]
        lib.pii_vault_rehydrate_for_tool_ex.restype = v

        # -- sealed-state persistence ----------------------------------------
        lib.pii_vault_export_sealed_entries_json.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_export_sealed_entries_json.restype = v

        lib.pii_vault_drain_dirty_sealed_entries_json.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_drain_dirty_sealed_entries_json.restype = v

        lib.pii_vault_import_sealed_entries_json.argtypes = [v, ctypes.c_char_p, ctypes.c_char_p]
        lib.pii_vault_import_sealed_entries_json.restype = ctypes.c_bool

        lib.pii_vault_export_sealed_state.argtypes = [v, ctypes.c_char_p]
        lib.pii_vault_export_sealed_state.restype = v

        lib.pii_vault_import_sealed_state.argtypes = [v, ctypes.c_char_p, ctypes.c_char_p]
        lib.pii_vault_import_sealed_state.restype = ctypes.c_bool

        # -- streaming --------------------------------------------------------
        lib.pii_stream_new.argtypes = []
        lib.pii_stream_new.restype = v

        lib.pii_stream_push_chunk.argtypes = [v, v, ctypes.c_char_p]
        lib.pii_stream_push_chunk.restype = v

        lib.pii_stream_flush.argtypes = [v, v]
        lib.pii_stream_flush.restype = v

        lib.pii_stream_free.argtypes = [v]
        lib.pii_stream_free.restype = None

        # -- strings -----------------------------------------------------------
        lib.pii_string_free.argtypes = [v]
        lib.pii_string_free.restype = None

    # -- helpers used by vault.py ----------------------------------------------
    def read_string(self, ptr: Optional[int]) -> Optional[str]:
        """Read and immediately free a returned ``*mut c_char``."""
        if not ptr:
            return None
        try:
            return ctypes.string_at(ptr).decode("utf-8")
        finally:
            self.cdll.pii_string_free(ptr)


_lib_instance: Optional[_Lib] = None


def get_lib() -> _Lib:
    global _lib_instance
    if _lib_instance is None:
        _lib_instance = _Lib()
    return _lib_instance


def read_and_free(lib: _Lib, ptr: Optional[int]) -> Optional[str]:
    return lib.read_string(ptr)


__all__ = ["get_lib", "read_and_free"]
