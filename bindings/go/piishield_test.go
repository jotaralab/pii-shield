package piishield

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
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
	if err := v.SetStatelessMode(true); err != nil {
		t.Fatalf("SetStatelessMode: %v", err)
	}
	ok, err := v.IsStatelessMode()
	if err != nil || !ok {
		t.Fatalf("IsStatelessMode: %v ok=%v", err, ok)
	}

	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// Concurrent read-only rehydrations must not deadlock.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Rehydrate(redacted); err != nil {
				t.Errorf("Rehydrate: %v", err)
			}
		}()
	}
	wg.Wait()
}

func bytes32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(100 + i)
	}
	return b
}

func TestCustomTOMLRejectsEmptySliceKey(t *testing.T) {
	// []byte{} is a non-nil empty slice: it must fail closed, not select
	// CSPRNG generation.
	if _, err := NewVaultWithCustomTOML("", customTOML, []byte{}); err == nil {
		t.Fatal("expected failure for empty non-nil key slice")
	}
}

func TestNULBytesRejected(t *testing.T) {
	v := requireVault(t)
	for _, s := range []string{"a\x00b", "\x00"} {
		if _, err := v.Redact(s); err == nil {
			t.Fatal("expected error for NUL input")
		}
	}
	if _, err := NewVaultWithLocales("global\x00"); err == nil {
		t.Fatal("expected error for NUL in locales")
	}
}

func TestClosedVaultReturnsErrVaultClosed(t *testing.T) {
	v := requireVault(t)
	redacted, err := v.Redact("NIK 3573012203950001")
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	v.Close()
	v.Close() // idempotent

	if _, err := v.Redact("x"); err != ErrVaultClosed {
		t.Fatalf("Redact after close: %v", err)
	}
	if _, err := v.Rehydrate(redacted); err != ErrVaultClosed {
		t.Fatalf("Rehydrate after close: %v", err)
	}
	if _, err := v.IsStatelessMode(); err != ErrVaultClosed {
		t.Fatalf("IsStatelessMode after close: %v", err)
	}
	if _, err := v.RehydrateForTool(redacted, InternalTrusted); err != ErrVaultClosed {
		t.Fatalf("RehydrateForTool after close: %v", err)
	}
}

func TestTwoPhaseSealAndClear(t *testing.T) {
	v := requireVault(t)
	if err := v.SetTokenFormat(TokenCompactHash); err != nil {
		t.Fatalf("SetTokenFormat: %v", err)
	}
	if _, err := v.Redact("NIK 3573012203950001"); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	sealed, err := v.SealDirtySealedEntriesJSON("aad:go2p")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) < 10 {
		t.Fatalf("seal output too small: %q", sealed)
	}
	var tokenMap map[string]string
	if err := json.Unmarshal([]byte(sealed), &tokenMap); err != nil {
		t.Fatalf("seal json: %v", err)
	}
	tokens := make([]string, 0, len(tokenMap))
	for tok := range tokenMap {
		tokens = append(tokens, tok)
	}
	tokensJSON, _ := json.Marshal(tokens)
	if err := v.ClearDirtyTokens(string(tokensJSON)); err != nil {
		t.Fatalf("ClearDirtyTokens: %v", err)
	}
	again, err := v.SealDirtySealedEntriesJSON("aad:go2p")
	if err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if again != "{}" {
		t.Fatalf("dirty set should be empty: %q", again)
	}
	if err := v.ClearDirtyTokens("not json"); err == nil {
		t.Fatal("expected error for invalid token JSON")
	}
}

func TestCustomTOMLCsprngStillRedacts(t *testing.T) {
	v, err := NewVaultWithCustomTOML("global", customTOML, nil)
	if err != nil {
		t.Fatalf("NewVaultWithCustomTOML with nil key: %v", err)
	}
	defer v.Close()
	redacted, err := v.Redact("ACC-123456")
	if err != nil || !strings.Contains(redacted, "<CUSTOM_ACC_") {
		t.Fatalf("csprng vault redact: %v %q", err, redacted)
	}
}

func TestSealDeterministicTokenSet(t *testing.T) {
	v := requireVault(t)
	if err := v.SetTokenFormat(TokenCompactHash); err != nil {
		t.Fatalf("SetTokenFormat: %v", err)
	}
	if _, err := v.Redact("NIK 3573012203950001"); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	a, err := v.SealDirtySealedEntriesJSON("aad:x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := v.SealDirtySealedEntriesJSON("aad:x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var m1, m2 map[string]string
	if err := json.Unmarshal([]byte(a), &m1); err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := json.Unmarshal([]byte(b), &m2); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !reflect.DeepEqual(keys(m1), keys(m2)) {
		t.Fatalf("token set changed between seals: %v vs %v", keys(m1), keys(m2))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
