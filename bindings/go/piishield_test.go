package piishield

import (
	"encoding/json"
	"strings"
	"testing"
)

const customTOML = `
locale = "custom"
name = "Custom"

[[rules]]
id = "CUSTOM_ACC"
tag_prefix = "CUSTOM_ACC"
regex = '\bACC-[0-9]{6}\b'
validator = "none"
`

func requireVault(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault()
	if err != nil {
		t.Skipf("shared library not built (run `cargo build -p pii-ffi`): %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func TestRedactRehydrateRoundtrip(t *testing.T) {
	v := requireVault(t)
	v.SetTokenFormat(TokenCompactHash)

	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(redacted, "<ID_NIK_") {
		t.Fatalf("expected token in %q", redacted)
	}
	if strings.Contains(redacted, "3573012203950001") {
		t.Fatalf("raw PII leaked: %q", redacted)
	}
	restored, err := v.Rehydrate(redacted)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != "NIK 3573012203950001" {
		t.Fatalf("roundtrip mismatch: %q", restored)
	}
}

func TestRedactJSONPreservesNumbers(t *testing.T) {
	v := requireVault(t)
	redacted, err := v.RedactJSON(`{"nik":"3573012203950001","order_id":1234567890123456}`)
	if err != nil {
		t.Fatalf("RedactJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(redacted), &parsed); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if got, ok := parsed["order_id"].(float64); !ok || got != 1234567890123456 {
		t.Fatalf("number mutated: %v", parsed)
	}
	if s, ok := parsed["nik"].(string); !ok || !strings.HasPrefix(s, "<ID_NIK_") {
		t.Fatalf("nik not redacted: %v", parsed["nik"])
	}
}

func TestUnknownLocaleFailsClosed(t *testing.T) {
	if _, err := NewVaultWithLocales("global_typo"); err == nil {
		t.Fatal("expected failure for unknown locale")
	}
}

func TestNewVaultWithKeyRejectsBadKey(t *testing.T) {
	if _, err := NewVaultWithKey("", make([]byte, 16)); err == nil {
		t.Fatal("expected failure for 16-byte key")
	}
}

func TestCustomTOML(t *testing.T) {
	key := bytes32()
	v, err := NewVaultWithCustomTOML("global", customTOML, key)
	if err != nil {
		t.Fatalf("NewVaultWithCustomTOML: %v", err)
	}
	defer v.Close()

	redacted, err := v.Redact("Account ACC-123456 opened")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(redacted, "<CUSTOM_ACC_") {
		t.Fatalf("custom rule did not fire: %q", redacted)
	}
	restored, err := v.Rehydrate(redacted)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != "Account ACC-123456 opened" {
		t.Fatalf("roundtrip mismatch: %q", restored)
	}
}

func TestCustomTOMLInvalidFailsClosed(t *testing.T) {
	bad := `
locale = "x"
name = "X"

[[rules]]
id = "BAD"
tag_prefix = "BAD"
regex = '(unbalanced['
`
	if _, err := NewVaultWithCustomTOML("", bad, nil); err == nil {
		t.Fatal("expected failure for invalid TOML regex")
	}
}

func TestCustomTOMLRejectsBadKeyLen(t *testing.T) {
	if _, err := NewVaultWithCustomTOML("", customTOML, make([]byte, 16)); err == nil {
		t.Fatal("expected failure for 16-byte key")
	}
	if _, err := NewVaultWithCustomTOML("", customTOML, make([]byte, 64)); err == nil {
		t.Fatal("expected failure for 64-byte key")
	}
}

func TestExfiltrationBlockedReportsToken(t *testing.T) {
	v := requireVault(t)
	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	_, err = v.RehydrateForTool(redacted, ExternalUntrusted)
	if err == nil {
		t.Fatal("expected exfiltration block")
	}
	exErr, ok := err.(*ExfiltrationError)
	if !ok {
		t.Fatalf("expected *ExfiltrationError, got %T", err)
	}
	if !strings.HasPrefix(exErr.Token, "<") {
		t.Fatalf("unexpected token %q", exErr.Token)
	}

	// Trusted tool rehydrates.
	trusted, err := v.RehydrateForTool(redacted, InternalTrusted)
	if err != nil {
		t.Fatalf("trusted rehydrate: %v", err)
	}
	if !strings.Contains(trusted, "3573012203950001") {
		t.Fatalf("trusted rehydrate mismatch: %q", trusted)
	}
}

func TestSealedEntriesCrossVault(t *testing.T) {
	key := bytes32()
	v1, err := NewVaultWithKey("", key)
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	defer v1.Close()
	v2, err := NewVaultWithKey("", key)
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	defer v2.Close()

	v1.SetTokenFormat(TokenCompactHash)
	redacted, err := v1.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	dirty, err := v1.DrainDirtySealedEntriesJSON("session:gotest")
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if err := v2.ImportSealedEntriesJSON(dirty, "session:gotest"); err != nil {
		t.Fatalf("Import: %v", err)
	}
	restored, err := v2.Rehydrate(redacted)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != "NIK 3573012203950001" {
		t.Fatalf("cross-vault mismatch: %q", restored)
	}
}

func TestSealedStateRoundtrip(t *testing.T) {
	key := bytes32()
	v1, err := NewVaultWithKey("", key)
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	defer v1.Close()
	v2, err := NewVaultWithKey("", key)
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	defer v2.Close()

	redacted, _ := v1.Redact("NIK 3573012203950001")
	state, err := v1.ExportSealedState("aad:go")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := v2.ImportSealedState(state, "aad:go"); err != nil {
		t.Fatalf("Import: %v", err)
	}
	restored, err := v2.Rehydrate(redacted)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != "NIK 3573012203950001" {
		t.Fatalf("state roundtrip mismatch: %q", restored)
	}
}

func TestStreamRehydratorSplitToken(t *testing.T) {
	v := requireVault(t)
	stream, err := NewStreamRehydrator()
	if err != nil {
		t.Fatalf("NewStreamRehydrator: %v", err)
	}
	defer stream.Close()

	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	half := len(redacted) / 2

	var sb strings.Builder
	part, err := stream.PushChunk(v, redacted[:half])
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	sb.WriteString(part)
	part, err = stream.PushChunk(v, redacted[half:])
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	sb.WriteString(part)
	part, err = stream.Flush(v)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	sb.WriteString(part)

	if sb.String() != "NIK 3573012203950001" {
		t.Fatalf("stream roundtrip mismatch: %q", sb.String())
	}
}

func TestSetStatelessModeAndConcurrentReads(t *testing.T) {
	v := requireVault(t)
	v.SetStatelessMode(true)

	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// Concurrent read-only rehydrations must not deadlock.
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer close(done)
			if _, err := v.Rehydrate(redacted); err != nil {
				t.Errorf("Rehydrate: %v", err)
			}
		}()
		<-done
		done = make(chan struct{})
	}
}

func bytes32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(100 + i)
	}
	return b
}
