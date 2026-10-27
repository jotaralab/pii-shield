# 🛡️ pii-shield

> **Sub-millisecond, Stateful PII Redaction & Reversible Pseudonymization Engine for AI Agents, MCP Servers, and Edge Runtimes.**  
> Built by [Jotara Lab](https://jotaralab.com) (`jotaralab/pii-shield`)

[![License](https://img.shields.io/badge/license-Apache%202.0%20%2F%20MIT-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Wasm Ready](https://img.shields.io/badge/wasm-%3C250KB-blueviolet.svg)](#wasm--cloudflare-workers)
[![UU PDP & International](https://img.shields.io/badge/PII-UU%20PDP%20%7C%20GDPR%20%7C%20CCPA-emerald.svg)](#built-in-entity-recognizers)

`pii-shield` is an embeddable, zero-backtracking PII firewall engineered in Rust. Unlike traditional regex scanners or heavy Python sidecars (like Microsoft Presidio), `pii-shield` uses a **Declarative i18n Rule Catalog**, a **3-Stage Cascading Sieve**, and a **Session-Scoped Bi-Directional Vault** so AI agents can reason over sensitive user data, execute database/MCP tool calls, and stream responses—without a single byte of raw PII ever reaching the LLM provider.

---

## ✨ Why `pii-shield`?

| Feature | `pii-shield` | Microsoft Presidio | Regex Scanners | LLM Guardrails |
| :--- | :--- | :--- | :--- | :--- |
| **P99 Latency** | **`< 1.0 ms`** | `45 - 180 ms` | Variable (ReDoS risk) | `250 - 800 ms` |
| **Memory Footprint** | **`< 5 MB`** | `600 MB+` (Python/spaCy) | `< 10 MB` | `2 GB+` |
| **Agent Tool Rehydration** | **Native (`PiiSessionVault`)** | Manual external DB | None | None |
| **Streaming Token Support** | **Stateful Lookahead Buffer** | Full-text only | Full-text only | Full-text only |
| **Indonesian / SEA PII (UU PDP)** | **Built-in Checksum Validation** | Custom plugins required | High false positives | Unreliable |
| **International PII (US, EU, SG)** | **Declarative TOML Catalog** | Hardcoded logic | High false positives | Unreliable |
| **Browser / Edge Wasm** | **Yes (`< 250KB` `.wasm`)** | No | JS-only | No |

---

## 🏗️ Architecture: The 3-Stage Cascading Sieve

```text
[Input Stream / Text]
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Word-Boundary Multi-Pattern DFA Scan                │
│ Fast O(N) candidate detection via regex-automata            │
└───────┬─────────────────────────────────────────────────────┘
        │ Candidate matches (start..end)
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: UTF-8 Safe Context Keyword & Priority Scoring       │
│ ±48 byte context window boosts confidence & disambiguates   │
└───────┬─────────────────────────────────────────────────────┘
        │ Scored candidate rules
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Algorithmic Checksum & Structural Verification      │
│ Luhn, Kemendagri NIK (38 prov), NPWP, SSN, IBAN, SG NRIC   │
└───────┬─────────────────────────────────────────────────────┘
        │ Verified EntityMatch
        ▼
   [PiiSessionVault: Consistent Pseudonymization Token]
```

---

## 📦 Workspace Crates

- **`crates/pii-core`**: Pure Rust engine. Declarative TOML locale catalogs (`rules/*.toml`), multi-pattern DFA scanner, algorithmic checksum verifiers (Luhn, Indonesian NIK/NPWP/Phone, US SSN, IBAN, SG NRIC), `PiiSessionVault` with `Zeroize` memory wiping, 3-layer taint-tracking ACLs, and streaming lookahead rehydration.
- **`crates/pii-wasm`**: `wasm-bindgen` bindings for Browser demos, Cloudflare Workers, and Vercel Edge middleware.
- **`crates/pii-ffi`**: C-ABI (`cbindgen`) thread-safe exports for zero-overhead embedding in Go, C/C++, Ruby, and Elixir.
- **`crates/pii-mcp-proxy`**: Fail-closed bidirectional STDIO wrapper for Model Context Protocol (MCP) servers that automatically rehydrates tool arguments and scrubs tool outputs.

---

## 🚀 Quick Start (Rust)

```rust
use pii_core::{PiiSessionVault, SecurityPolicy, ToolTrustLevel};

fn main() {
    let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);

    // 1. Scrub inbound prompt before sending to LLM
    let raw_prompt = "Tolong kirim invoice ke budi.santoso@gmail.com untuk NIK 3573012203950001.";
    let safe_prompt = vault.redact(raw_prompt);
    assert_eq!(
        safe_prompt,
        "Tolong kirim invoice ke <EMAIL_1> untuk NIK <ID_NIK_1>."
    );

    // 2. Rehydrate LLM tool call arguments for internal DB execution
    let llm_tool_args = r#"{"nik": "<ID_NIK_1>", "notify": "<EMAIL_1>"}"#;
    let real_args = vault
        .rehydrate_for_tool(llm_tool_args, ToolTrustLevel::InternalTrusted)
        .expect("Trusted internal tool allowed");

    // 3. Rehydrate final LLM response back to the user
    let llm_reply = "Invoice untuk <ID_NIK_1> telah dikirim ke <EMAIL_1>.";
    let final_reply = vault.rehydrate(llm_reply);
    assert_eq!(
        final_reply,
        "Invoice untuk 3573012203950001 telah dikirim ke budi.santoso@gmail.com."
    );
}
```

---

## 🌍 Contributing & Extending PII Rules

`pii-shield` supports both **built-in open-source locale contributions** and **runtime rule extension without modifying code**.

For detailed step-by-step instructions and the full TOML schema reference, see [**docs/contributing-pii-rules.md**](docs/contributing-pii-rules.md).

- **Option 1: Built-in Locale Contribution**: Add a declarative `crates/pii-core/rules/<locale>.toml` file with `valid_samples` and `invalid_samples` test cases.
- **Option 2: Runtime Extension**: Call `PiiCatalog::merge_toml_str()` in Rust or pass `--locales` to `pii-mcp-proxy` to load custom regional rules dynamically.

```toml
[[rules]]
id = "BR_CPF"
tag_prefix = "BR_CPF"
description = "Brazilian Cadastro de Pessoas Físicas (CPF)"
regex = '\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b'
validator = "none" # or register a built-in checksum algorithm
priority = 90
context_keywords = ["cpf", "receita", "brasil"]
valid_samples = ["123.456.789-00"]
invalid_samples = ["12345678900"]
```

Run `cargo test --workspace` to automatically compile and verify the rules.

---

## 🔍 Built-in Entity Recognizers & Checksum Validators

1. **`ID_NIK` (Indonesian National ID / KTP)**: 16-digit structural validation checking all 38 Kemendagri/BPS province codes (`11`–`96`), leap-year-aware `DDMMYY` date of birth (including `+40` female offset), and non-zero serial suffix.
2. **`ID_NPWP` (Indonesian Tax ID)**: 15-digit and 16-digit (PMK 112/2022 NITKU) formatted and unformatted tax identification numbers.
3. **`CREDIT_CARD`**: 13–19 digit payment cards (Visa, Mastercard, Amex, Discover) verified in-memory via the **Luhn algorithm** to eliminate false positives.
4. **`EMAIL`**: Robust word-boundary email matcher with domain validation.
5. **`PHONE_ID`**: Indonesian cellular and landline numbers (`+62`, `62`, `08xx`) verified against allocated operator prefixes and area codes.
6. **`US_SSN`**: 9-digit United States Social Security Number excluding invalid area (`000`, `666`, `900`–`999`), group, and serial numbers.
7. **`IBAN`**: International Bank Account Number verified via ISO 7064 Mod 97-10 checksum.
8. **`SG_NRIC`**: Singapore National Registration Identity Card / FIN Mod-11 checksum.

---

## 🛠️ MCP Proxy Usage

Run the zero-trust STDIO MCP proxy wrapper with a fail-closed tool ACL:

```bash
# Allow only trusted internal query tools to rehydrate PII:
pii-mcp-proxy --trusted-tools query_db,lookup_user -- npx -y @modelcontextprotocol/server-postgres postgresql://...
```

---

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
