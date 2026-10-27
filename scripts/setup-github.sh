#!/usr/bin/env bash
set -euo pipefail

# Default to jotaralab/pii-shield, override with ORG=jotaralab ./scripts/setup-github.sh if desired
ORG="${ORG:-jotaralab}"
REPO="pii-shield"

# Check if git is already initialized
if [ ! -d ".git" ]; then
  echo "🚀 Initializing git repository for ${ORG}/${REPO}..."
  git init -b main
  git add .
  git commit -m "feat: initial scaffold of pii-shield core engine, vault, wasm, ffi, and mcp-proxy"
else
  echo "ℹ️ Git repository already initialized."
fi

# Check if remote origin exists
if git remote | grep -q "^origin$"; then
  echo "ℹ️ Remote 'origin' already exists."
else
  echo "🌐 Creating public GitHub repository ${ORG}/${REPO}..."
  gh repo create "${ORG}/${REPO}" \
    --public \
    --description "Sub-millisecond, stateful PII redaction & reversible pseudonymization engine for AI agents and edge runtimes." \
    --homepage "https://jotaralab.com" \
    --source=. \
    --remote=origin \
    --push || true
fi

echo "🏷️ Adding repository topics..."
gh repo edit "${ORG}/${REPO}" \
  --add-topic "pii-redaction" \
  --add-topic "ai-security" \
  --add-topic "llm-guardrails" \
  --add-topic "mcp" \
  --add-topic "rust" \
  --add-topic "webassembly" \
  --add-topic "uu-pdp" || true

echo "✅ Repository setup complete: https://github.com/${ORG}/${REPO}"
