# Python bindings for pii-shield

Idiomatic `ctypes` wrapper over the `pii-ffi` C-ABI.

```sh
cargo build -p pii-ffi                     # from the workspace root
pip install -e bindings/python
```

## Usage

```python
from pii_shield import PiiSessionVault, TokenFormat

vault = PiiSessionVault(locales_csv="global,id")
vault.set_token_format(TokenFormat.CompactHash)

redacted = vault.redact("NIK 3573012203950001")   # NIK <ID_NIK_...>
original = vault.rehydrate(redacted)               # NIK 3573012203950001
```

All string-returning FFI functions follow a zero-leak lifecycle
(`c_void_p` restype + explicit `pii_string_free`), and invalid
configuration (unknown locales, bad TOML, malformed keys) fails closed
with `ValueError`.
