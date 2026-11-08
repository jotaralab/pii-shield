"""Python SDK tests for the pii-shield bindings.

Run from the workspace root (builds nothing; requires the shared library)::

    cargo build -p pii-ffi
    python3 -m unittest discover -s bindings/python/tests -v
"""
import ctypes
import json
import os
import sys
import unittest

# Make the bindings/python dir visible to `pii_shield` regardless of cwd.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from pii_shield import (  # noqa: E402
    ExfiltrationBlockedError,
    PiiSessionVault,
    StreamingRehydrator,
    TokenFormat,
    ToolTrustLevel,
)

CUSTOM_TOML = """
locale = "custom"
name = "Custom"

[[rules]]
id = "CUSTOM_ACC"
tag_prefix = "CUSTOM_ACC"
regex = '\\bACC-[0-9]{6}\\b'
validator = "none"
"""


class VaultTest(unittest.TestCase):
    def test_redact_rehydrate_roundtrip(self):
        with PiiSessionVault() as vault:
            vault.set_token_format(TokenFormat.CompactHash)
            redacted = vault.redact("NIK 3573012203950001")
            self.assertIn("<ID_NIK_", redacted)
            self.assertNotIn("3573012203950001", redacted)
            self.assertEqual(vault.rehydrate(redacted), "NIK 3573012203950001")

    def test_redact_json_preserves_numbers(self):
        with PiiSessionVault() as vault:
            redacted = vault.redact_json('{"nik":"3573012203950001","order_id":1234567890123456}')
            parsed = json.loads(redacted)
            self.assertEqual(parsed["order_id"], 1234567890123456)
            self.assertTrue(parsed["nik"].startswith("<ID_NIK_"))

    def test_unknown_locale_fails_closed(self):
        with self.assertRaises(ValueError):
            PiiSessionVault(locales_csv="global_typo")

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            PiiSessionVault(key=b"short")

    def test_custom_toml(self):
        vault = PiiSessionVault(locales_csv="global", custom_toml=CUSTOM_TOML)
        try:
            redacted = vault.redact("Account ACC-123456 opened")
            self.assertIn("<CUSTOM_ACC_", redacted)
            self.assertEqual(vault.rehydrate(redacted), "Account ACC-123456 opened")
        finally:
            vault.close()

    def test_custom_toml_invalid_fails_closed(self):
        with self.assertRaises(ValueError):
            PiiSessionVault(
                locales_csv="global",
                custom_toml='locale = "x"\nname = "X"\n\n[[rules]]\nid = "BAD"\n'
                            'tag_prefix = "BAD"\nregex = "(unbalanced["\n',
            )

    def test_csprng_key_with_custom_toml(self):
        vault = PiiSessionVault(custom_toml=CUSTOM_TOML)
        try:
            redacted = vault.redact("ACC-123456")
            self.assertIn("<CUSTOM_ACC_", redacted)
        finally:
            vault.close()

    def test_exfiltration_blocked_with_token(self):
        with PiiSessionVault() as vault:
            redacted = vault.redact("NIK 3573012203950001")
            # Untrusted tool must be blocked and report the exact token.
            with self.assertRaises(ExfiltrationBlockedError) as ctx:
                vault.rehydrate_for_tool(redacted, ToolTrustLevel.ExternalUntrusted)
            self.assertTrue(ctx.exception.token.startswith("<"))
            # Trusted tool succeeds and rehydrates.
            token = ctx.exception.token
            trusted = vault.rehydrate_for_tool(json.dumps({"nik": token}), True)
            self.assertIn("3573012203950001", trusted)

    def test_sealed_entries_roundtrip_between_vaults(self):
        shared = bytes(range(32))
        v1 = PiiSessionVault(key=shared)
        v2 = PiiSessionVault(key=shared)
        try:
            v1.set_token_format(TokenFormat.CompactHash)
            redacted = v1.redact("NIK 3573012203950001")
            dirty = v1.drain_dirty_sealed_entries_json("session:pytest")
            self.assertTrue(len(json.loads(dirty)) > 0)
            v2.import_sealed_entries_json(dirty, "session:pytest")
            self.assertEqual(v2.rehydrate(redacted), "NIK 3573012203950001")
        finally:
            v1.close()
            v2.close()

    def test_sealed_state_roundtrip(self):
        shared = bytes(range(32))
        v1 = PiiSessionVault(key=shared)
        v2 = PiiSessionVault(key=shared)
        try:
            redacted = v1.redact("NIK 3573012203950001")
            state = v1.export_sealed_state("aad:test")
            self.assertTrue(state)
            v2.import_sealed_state(state, "aad:test")
            self.assertTrue("<ID_NIK_" in redacted or "<PII:" in redacted)
            self.assertEqual(v2.rehydrate(redacted), "NIK 3573012203950001")
        finally:
            v1.close()
            v2.close()

    def test_import_bad_json_raises(self):
        with PiiSessionVault() as vault:
            with self.assertRaises(ValueError):
                vault.import_sealed_entries_json("not json", "aad")


class StreamingTest(unittest.TestCase):
    def test_split_token_rehydrate(self):
        with PiiSessionVault() as vault:
            redacted = vault.redact("NIK 3573012203950001")
            with StreamingRehydrator() as stream:
                half = len(redacted) // 2
                out = stream.push_chunk(redacted[:half], vault)
                out += stream.push_chunk(redacted[half:], vault)
                out += stream.flush(vault)
            self.assertEqual(out, "NIK 3573012203950001")


if __name__ == "__main__":
    unittest.main()
