# 🛡️ pii-shield

> **Sub-millisecond, Stateful PII Redaction & Reversible Pseudonymization Engine for AI Agents, MCP Servers, and Edge Runtimes.**  
> Built by [Jotara Lab](https://jotaralab.com) (`jotaralab/pii-shield`)

[![License](https://img.shields.io/badge/license-Apache%202.0%20%2F%20MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Wasm Ready](https://img.shields.io/badge/wasm-%3C250KB-blueviolet.svg)](#wasm--cloudflare-workers)
[![UU PDP Compliant](https://img.shields.io/badge/Indonesia-UU%20PDP%20Ready-emerald.svg)](#built-in-entity-recognizers)

`pii-shield` is an embeddable, zero-backtracking PII firewall engineered in Rust. Unlike traditional regex scanners or heavy Python sidecars (like Microsoft Presidio), `pii-shield` uses a **3-Stage Cascading Sieve** and a **Session-Scoped Bi-Directional Vault** so AI agents can reason over sensitive user data, execute database/MCP tool calls, and stream responses—without a single byte of raw PII ever reaching the LLM provider.

---

## ✨ Why `pii-shield`?

| Feature | `pii-shield` | Microsoft Presidio | Regex Scanners | LLM Guardrails |
| :--- | :--- | :--- | :--- | :--- |
| **P99 Latency** | **`< 1.0 ms`** | `45 - 180 ms` | Variable (ReDoS risk) | `250 - 800 ms` |
| **Memory Footprint** | **`< 5 MB`** | `600 MB+` (Python/spaCy) | `< 10 MB` | `2 GB+` |
| **Agent Tool Rehydration** | **Native (`PiiSessionVault`)** | Manual external DB | None | None |
| **Streaming Token Support** | **Stateful Lookahead Buffer** | Full-text only | Full-text only | Full-text only |
| **Indonesian / SEA PII (UU PDP)** | **Built-in Checksum Validation** | Custom plugins required | High false positives | Unreliable |
| **Browser / Edge Wasm** | **Yes (`< 250KB` `.wasm`)** | No | JS-only | No |

---

## 🏗️ Architecture: The 4 Agent Interception Boundaries

```text
[User] 
  │  1. Prompt Scrub ("Cek pesanan Budi, NIK 3573012203950001")
  ▼
┌─────────────────────────────────────────────────────────────┐
│             PII SHIELD AGENT MIDDLEWARE (In-VPC)            │
│  Session Vault: { "<ID_NIK_1>": "3573012203950001", ... }   │
└───────┬──────────────────────────────▲──────────────────────┘
        │ Sanitized ("Cek <PER_1>,     │ Tool Call:
        │            NIK <ID_NIK_1>")  │ query_db(nik="<ID_NIK_1>")
        ▼                              │
   [LLM API] ──────────────────────────┘
        ▲
        │ 4. Sanitized Tool Output ("Status <ID_NIK_1>: Dikirim ke <EMAIL_1>")
┌───────┴─────────────────────────────────────────────────────┐
│                MCP / TOOL EXECUTION PROXY                   │
│  2. Rehydrate Args: "<ID_NIK_1>" ──► "3573012203950001"     │
│  3. Scrub DB/API Response before returning to LLM context   │
└───────┬──────────────────────────────▲──────────────────────┘
        │ Real Query                   │ Raw DB Row (contains address, phone)
        ▼                              │
  [Internal DB / ERP / External APIs / MCP Servers]
```

---

## 📦 Workspace Crates

- **`crates/pii-core`**: Pure Rust engine. Multi-pattern DFA scanner, algorithmic checksum verifiers (Luhn, Indonesian NIK, NPWP), `PiiSessionVault` with `Zeroize` memory wiping, taint-tracking ACLs, and streaming lookahead rehydration.
- **`crates/pii-wasm`**: `wasm-bindgen` bindings for Browser demos, Cloudflare Workers, and Vercel Edge middleware.
- **`crates/pii-ffi`**: C-ABI (`cbindgen`) exports for zero-overhead embedding in Go, C/C++, Ruby, and Elixir.
- **`crates/pii-mcp-proxy`**: Drop-in STDIO wrapper for Model Context Protocol (MCP) servers that automatically rehydrates tool arguments and scrubs tool outputs.

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

## 🔍 Built-in Entity Recognizers & Checksum Validators

1. **`ID_NIK` (Indonesian National ID / KTP)**: 16-digit structural validation checking valid province code prefixes (`11`–`94`), `DDMMYY` date of birth validation (including `+40` female day offset), and non-zero serial suffix.
2. **`ID_NPWP` (Indonesian Tax ID)**: 15-digit and 16-digit formatted/unformatted tax identification numbers.
3. **`CREDIT_CARD`**: 13–19 digit payment cards verified in-memory via the **Luhn algorithm** to eliminate false positives on arbitrary order/tracking numbers.
4. **`EMAIL`**: RFC-5322 compliant deterministic automaton matcher.
5. **`PHONE_ID`**: Indonesian mobile and landline numbers (`+62`, `62`, `08xx`) with carrier prefix verification.

---

## 🛠️ Publishing to GitHub (`jotaralab/pii-shield`)

Run the included setup script with the GitHub CLI (`gh`):

```bash
chmod +x scripts/setup-github.sh
./scripts/setup-github.sh
```

---

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
