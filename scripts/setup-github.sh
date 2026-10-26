#!/usr/bin/env bash
set -euo pipefail

# Default to jotaralab/pii-shield, override with ORG=jotralab ./scripts/setup-github.sh if desired
ORG="${ORG:-jotaralab}"
REPO="pii-shield"

echo "🚀 Initializing git repository for ${ORG}/${REPO}..."
git init -b main
git add .
git commit -m "feat: initial scaffold of pii-shield core engine, vault, wasm, ffi, and mcp-proxy"

echo "🌐 Creating public GitHub repository ${ORG}/${REPO}..."
gh repo create "${ORG}/${REPO}" \
  --public \
  --description "Sub-millisecond, stateful PII redaction & reversible pseudonymization engine for AI agents and edge runtimes." \
  --homepage "https://jotaralab.com" \
  --source=. \
  --remote=origin \
  --push

echo "🏷️ Adding repository topics..."
gh repo edit "${ORG}/${REPO}" \
  --add-topic "pii-redaction" \
  --add-topic "ai-security" \
  --add-topic "llm-guardrails" \
  --add-topic "mcp" \
  --add-topic "rust" \
  --add-topic "webassembly" \
  --add-topic "uu-pdp"

echo "✅ Repository live at: https://github.com/${ORG}/${REPO}"
