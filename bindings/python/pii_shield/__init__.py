"""Idiomatic Python SDK for pii-shield.

Example::

    from pii_shield import PiiSessionVault

    vault = PiiSessionVault()
    redacted = vault.redact("User NIK 3573012203950001")
    print(redacted)  # User NIK <ID_NIK_...>
"""
from pii_shield.vault import (
    ExfiltrationBlockedError,
    PiiSessionVault,
    StreamingRehydrator,
    TokenFormat,
    ToolTrustLevel,
)

__version__ = "0.1.0"

__all__ = [
    "ExfiltrationBlockedError",
    "PiiSessionVault",
    "StreamingRehydrator",
    "TokenFormat",
    "ToolTrustLevel",
]
