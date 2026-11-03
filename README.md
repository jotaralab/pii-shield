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
- **Option 2: Runtime Extension**: Call `PiiCatalog::merge_toml_str()` in Rust, or pass `--rules-file ./rules/<locale>.toml` to `pii-mcp-proxy` to load custom regional rules dynamically.

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

**GDPR (European Union & UK) — `eu` locale:**

- **`DE_STEUER_ID`**: 11-digit German Steuer-Identifikationsnummer with ISO 7064 Mod 11,10 check digit and dedup-protected digit histogram (single pair or single triple, no 3-digit runs).
- **`FR_NIR`**: 15-character French social security number (NIR) with Mod 97 key check, Corse `2A`/`2B` normalization, and overseas DOM-TOM department validation (`971–978`, `984–988`).
- **`ES_DNI` / NIE**: 9-character Spanish national ID with Mod 23 letter check (`TRWAGMYFPDXBNJZSQVHLCKE`), including `X/Y/Z` foreigner prefixes.
- **`IT_CODICE_FISCALE`**: 16-character Italian fiscal code with official odd/even check-char tables and omocodia day decoding (`L→0 … V→9`).
- **`NL_BSN`**: 9-digit Dutch Burgerservicenummer validated with the 11-proef (dot-separated or contiguous).
- **`PL_PESEL`**: 11-digit Polish national number with century-aware month encoding, full Gregorian date validation (leap years 1800–2200), and weighted check digit.
- **`UK_NHS`**: 10-digit UK National Health Service number verified with the Mod 11 algorithm (spaced, hyphenated, or contiguous).
- **`UK_NINO`**: 9-character UK National Insurance number with reserved first/second letter rules and forbidden prefix list (`BG`, `GB`, `NK`, `KN`, `TN`, `NT`, `ZZ`).

**CCPA / US — `us` locale:**

- **`US_ITIN`**: Individual Taxpayer Identification Number (`9XX-XX-XXXX`) with IRS group-range validation — mathematically disjoint from `US_SSN`, which rejects the 900–999 area range.
- **`US_ROUTING_ABA`**: 9-digit ABA transit number with Federal Reserve prefix ranges (`01–12`, `21–32`, `61–72`, `80`) and the weight `3-7-1` mod 10 checksum.
- **`US_CA_DL`**: California driver's license (`\b[A-Z][0-9]{7}\b`) with **`require_context = true`** — matched only when a keyword like `driver`, `license`, `dl`, `dmv`, or `california` appears within ±48 bytes, so product SKUs, ticket IDs and commit SHAs are never falsely redacted.

All new validators enforce strict separator discipline: leading/trailing separators, consecutive separators (`--`, `  `, `..`), and stray characters are rejected up front. New declarative rules may also opt into context gating with `require_context = true` combined with `context_keywords` (see [docs/contributing-pii-rules.md](docs/contributing-pii-rules.md)).

---

## 🛠️ MCP Proxy Usage

Run the zero-trust STDIO MCP proxy wrapper with a fail-closed tool ACL:

```bash
# Allow only trusted internal query tools to rehydrate PII:
pii-mcp-proxy --trusted-tools query_db,lookup_user -- npx -y @modelcontextprotocol/server-postgres postgresql://...
```

### Built-in locales & dynamic custom rules

The proxy fails closed: unknown flags, unknown locales, unreadable/invalid rule
files, invalid regexes, or a merged catalog with 0 rules all exit with status
code `2` and an error on `stderr`.

```bash
# Built-in locales (default: global,id). Other built-ins: us, eu, sg, none
pii-mcp-proxy --locales global,id -- npx .../server

# Load external TOML rule files via --rules-file (repeatable or comma-separated).
# Built-ins load first, then each rules file in order; custom rules with an
# existing rule id replace that rule, new ids compete by `priority`.
pii-mcp-proxy \
    --rules-file ./rules/br.toml,./rules/de.toml \
    --trusted-tools query_db \
    -- npx .../server

# Rule file paths are also accepted inline in --locales:
pii-mcp-proxy --locales "global,./rules/br.toml" -- npx .../server

# Only custom rules, no built-in locales:
pii-mcp-proxy --locales none --rules-file ./rules/br.toml -- npx .../server
```

### Token formats & explicit session key

```bash
--token-format sequential        # <EMAIL_1> (default)
--token-format compact-hash      # <EMAIL_4F7Q01>, deterministic per session key
--token-format stateless-sealed  # <PII:EMAIL:HEX>, self-contained encrypted token

PII_SHIELD_SESSION_KEY=  # 64-char hex (32 bytes); required for cross-process
                         # sealed-token decryption (--stdio-filter always needs it)
PII_SHIELD_TOKEN_FORMAT= # env alias for --token-format
PII_SHIELD_STATELESS=1   # env alias for stateless-sealed when --token-format is omitted
```

`PiiCatalog::merge_toml_str()` validates every rule: `tag_prefix` must be
non-empty uppercase `[A-Z0-9_]+`, the regex must compile with the scanner's
syntax config (bounded NFA/DFA sizes), and `pii-mcp-proxy` refuses to start if
the merged catalog would contain no rules — invalid configuration can never
silently disable PII redaction. STDIO filter mode (`--stdio-filter`, or running
without a child command) requires `--token-format stateless-sealed` plus
`PII_SHIELD_SESSION_KEY`, since stateful tokens cannot be generated in
a redaction-less filter pass.

Run `pii-mcp-proxy --help` / `--version` for the full CLI reference.

---

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
