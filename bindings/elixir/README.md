# Elixir bindings for pii-shield

Erlang NIF wrapper around `libpii_ffi`. Build the Rust shared library first
from the workspace root (`cargo build -p pii-ffi`) — the Mix precompile hook
compiles `c_src/pii_shield_nif.c` and links it against `libpii_ffi`.

```elixir
{:pii_shield, "~> 0.1.0"}
```

Set `PII_SHIELD_LIB_PATH` to point at the shared library if it lives
somewhere unusual.
