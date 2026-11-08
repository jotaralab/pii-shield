# Bindings — Multi-Language SDK Packages

Idiomatic SDKs for embedding `pii-shield` into Python, Go, Ruby, and Elixir
agents through the C-ABI exported by `crates/pii-ffi`.

## Building the shared library first

Every binding loads `libpii_ffi.{so,dylib}` / `pii_ffi.dll` at runtime:

```sh
cargo build -p pii-ffi            # debug build -> target/debug
cargo build -p pii-ffi --release  # release build -> target/release
```

| Language | Directory | Library search | Test |
| :--- | :--- | :--- | :--- |
| Python | `bindings/python` | `PII_SHIELD_LIB_PATH`, then `target/{release,debug}` | `python3 -m unittest discover -s bindings/python/tests -v` |
| Go     | `bindings/go`     | `PII_SHIELD_LIB_PATH`, then `target/{release,debug}` | `go test -v ./...` |
| Ruby   | `bindings/ruby`   | `PII_SHIELD_LIB_PATH`, then `target/{release,debug}` | `ENV["PII_SHIELD_LIB_PATH"]=... ruby -Ilib -e 'require "pii_shield_test"'` |
| Elixir | `bindings/elixir` | `PII_SHIELD_LIB_PATH` (NIF shim compile flag) | `mix test` |

## Memory-safety contract (all languages)

Every C function returning `char *` returns a Rust-owned heap allocation that
**must** be released with `pii_string_free`. Each binding guarantees this:

- **Python** (`ctypes`): string-returning functions use `restype = c_void_p`
  so ctypes never copies the pointer and loses it; values read via
  `ctypes.string_at(ptr)` and freed in `finally:`.
- **Go** (`cgo`): input `C.CString` freed with `defer C.free`, outputs freed
  with `defer C.pii_string_free`.
- **Ruby** (`ffi`): `:pointer` return type + `read_string` + `pii_string_free`
  inside `ensure`.
- **Elixir** (NIF shim): harms' `ErlNifResourceType` destructors free vaults
  and streams; strings copied into Erlang binaries before freeing.
