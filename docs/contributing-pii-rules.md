# 🌍 Contributing & Extending PII Rules

`pii-shield` uses a declarative, data-driven architecture. Adding or customizing regional PII rules does **not** require modifying core regex engine code.

There are two primary approaches to adding PII rules:
1. **Option 1: Contributing a Built-in Locale Pack** (Contributing to the open-source repository).
2. **Option 2: Runtime Extension** (Loading custom rules dynamically in your application without modifying the engine).

---

## Option 1: Contributing a Built-in Locale Pack

If you want to contribute built-in support for a new country or jurisdiction (e.g., Brazil `br`, United Kingdom `uk`, Japan `jp`), follow these steps:

### 1. Create a Locale TOML File

Create a new file under `crates/pii-core/rules/<locale>.toml` (for example, `crates/pii-core/rules/br.toml`):

```toml
locale = "br"
name = "Brazil (LGPD)"

[[rules]]
id = "BR_CPF"
tag_prefix = "BR_CPF"
description = "Brazilian Cadastro de Pessoas Físicas (CPF)"
regex = '\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b'
validator = "none" # or a registered checksum validator (e.g., "br_cpf", "luhn")
priority = 90
context_keywords = ["cpf", "receita", "brasil", "documento"]
valid_samples = ["123.456.789-00", "987.654.321-99"]
invalid_samples = ["12345678900", "00-123456789"]

[[rules]]
id = "PHONE_BR"
tag_prefix = "PHONE_BR"
description = "Brazilian phone numbers"
regex = '(?:\+55[ ]*)?(?:\([1-9]{2}\)|[1-9]{2})[ ]*(?:9[0-9]{4}|[2-8][0-9]{3})[ \-]?[0-9]{4}\b'
validator = "e164_phone"
priority = 75
context_keywords = ["telefone", "celular", "fone", "whatsapp"]
valid_samples = ["+55 (11) 98765-4321", "11 98765-4321", "(21) 3456-7890"]
invalid_samples = ["123-45", "000-0000"]
```

### 2. Rule Schema Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `String` | Yes | Unique rule identifier across all catalogs (e.g. `BR_CPF`, `US_SSN`). |
| `tag_prefix` | `String` | Yes | Token label used in pseudonymization (e.g. `<BR_CPF_1>` or `<PII:BR_CPF:HEX>`). |
| `description` | `String` | No | Human-readable explanation of the entity. |
| `regex` | `String` | Yes | Word-boundary safe regular expression (`\b`). Avoid literal space characters at borders. |
| `validator` | `String` | No | Algorithmic Stage-3 verifier (`"none"`, `"luhn"`, `"iban_mod97"`, `"e164_phone"`, etc.). Defaults to `"none"`. |
| `priority` | `u16` | No | Disambiguation priority score (default `50`). Higher scores take precedence when candidate spans overlap. |
| `context_keywords`| `Vec<String>`| No | Words within a $\pm 48$-byte window that boost match confidence score by `+25`. |
| `valid_samples` | `Vec<String>`| No | Test samples that **must** match during automated test verification. |
| `invalid_samples` | `Vec<String>`| No | Test samples that **must be rejected** during automated test verification. |

### 3. Register the Locale in `catalog.rs`

In `crates/pii-core/src/catalog.rs`:
1. Include the new TOML file:
   ```rust
   pub const BR_TOML: &str = include_str!("../rules/br.toml");
   ```
2. Add the locale mapping to `PiiCatalog::with_locales`:
   ```rust
   "br" => catalog.merge_toml_str(BR_TOML)?,
   ```

---

## Option 2: Runtime Extension (Without Modifying the Engine)

Applications using `pii-shield` can dynamically load custom rules or private entity catalogs at runtime from external files, databases, or environment variables.

### In Rust

```rust
use pii_core::{PiiCatalog, PiiSessionVault};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize built-in rules (e.g. global + Indonesian)
    let mut catalog = PiiCatalog::with_locales(&["global", "id"])?;

    // 2. Load custom proprietary or regional rules from a TOML file
    let custom_toml = fs::read_to_string("custom_rules.toml")?;
    catalog.merge_toml_str(&custom_toml)?;

    // 3. Initialize vault with the merged catalog
    let mut vault = PiiSessionVault::from_catalog(catalog);

    let prompt = "Kirim laporan ke BR_CPF 123.456.789-00 dan NIK 3573012203950001";
    let scrubbed = vault.redact(prompt);
    println!("{}", scrubbed);
    // Output: "Kirim laporan ke BR_CPF <BR_CPF_1> dan NIK <ID_NIK_1>"

    Ok(())
}
```

### In MCP Proxy (`pii-mcp-proxy`)

When wrapping Model Context Protocol (MCP) servers, specify which locale packs to activate via CLI flags:

```bash
# Enable Global, US, EU, and Singapore rules with a fail-closed tool ACL
pii-mcp-proxy --locales global,us,eu,sg --trusted-tools query_db -- <mcp-server-command>
```

### In WebAssembly (JavaScript / TypeScript)

```typescript
import { WasmPiiSession } from "pii-shield-wasm";

// Initialize session with desired locale packs
const session = WasmPiiSession.with_locales("global,us,eu,sg");

// Redact prompt before sending to LLM
const scrubbed = session.redact("Call me at +1 (555) 234-5678 or SSN 123-45-6789");
console.log(scrubbed);
// Output: "Call me at <PHONE_US_1> or SSN <US_SSN_1>"
```

---

## Adding Custom Checksum Algorithms

If a country's PII requires specialized mathematical validation (like French NIR / INSEE checksum or Italian Codice Fiscale):

1. Add the modular validator function under `crates/pii-core/src/checksum/` (e.g. `checksum/br.rs` for `validate_br_cpf`).
2. Expose it in `crates/pii-core/src/checksum/mod.rs`:
   - Register it in `validate_by_name(validator: &str, slice: &str) -> bool`.
   - Register it in `is_known_validator(name: &str) -> bool`.
3. Reference `validator = "br_cpf"` in your TOML rule specification.
