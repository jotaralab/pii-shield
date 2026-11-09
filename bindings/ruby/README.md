# Ruby bindings for pii-shield

FFI-based Ruby SDK over the `libpii_ffi` C-ABI.

## Install / build

Build the shared library from the workspace root first:

```bash
cargo build -p pii-ffi
```

Dependency discovery: `PII_SHIELD_LIB_PATH` → workspace `target/{release,debug}` →
system loader.

Gem runtime dependency: the `ffi` gem (`gem install ffi --no-document`).

## Usage

```ruby
require "pii_shield"

# Default locales ("global,id") and a CSPRNG session key
vault = PiiShield::Vault.new

# Explicit locales / 32-byte shared key / custom TOML rules
vault = PiiShield::Vault.new(locales_csv: "global,id", key: 32_byte_key)
vault = PiiShield::Vault.new(locales_csv: "global", custom_toml: toml, key: key)

redacted = vault.redact("NIK 3573012203950001")   # => "NIK <ID_NIK_A1BWQ2>"
vault.rehydrate(redacted)                          # => "NIK 3573012203950001"

# ACL-enforced tool rehydration; raises ExfiltrationBlockedError with the
# exact offending token for untrusted tools
vault.rehydrate_for_tool(payload, trusted: true)
vault.rehydrate_for_tool(payload, trusted: false)

# Two-phase dirty sync (persist entries, then clear)
sealed = vault.seal_dirty_sealed_entries_json("aad")   # snapshot; does not clear
vault.clear_dirty_tokens(JSON.generate(JSON.parse(sealed).keys))

# Full-state export/import between vaults sharing a key
state = vault.export_sealed_state("aad")
other.import_sealed_state(state, "aad")

# Streaming rehydration of tokens split across SSE chunks
stream = PiiShield::StreamingRehydrator.new
stream.push_chunk(chunk1, vault)
stream.push_chunk(chunk2, vault)
stream.flush(vault)

vault.close
```

## Memory-safety contract

* String-returning C functions are declared with `return_type :pointer` (not
  `:string`) so the raw Rust heap pointer stays visible and is freed with
  `pii_string_free` inside an `ensure` block — nothing leaks even if reading
  the string raises.
* Vault/stream handles are owned by `FFI::AutoPointer` and freed exactly once;
  `close` is idempotent and guarded by a `Mutex` so it cannot race an
  in-flight FFI call (FFI calls release the GVL).
* Input strings must be valid UTF-8 without interior NUL bytes; violations
  raise `ArgumentError` instead of silently truncating at the C boundary.

## Tests

```bash
ruby -Ilib:test test/test_pii_shield.rb
```
