// Package piishield provides idiomatic Go bindings for pii-shield, the
// sub-millisecond PII redaction & reversible pseudonymization engine.
//
// The package wraps the C-ABI of libpii_ffi via cgo. All functions returning
// C strings are freed with C.pii_string_free (input C.CString allocations are
// freed with C.free) so no Rust heap memory leaks.
//
// Prerequisite: build the shared library from the workspace root:
//
//	cargo build -p pii-ffi
//
// The linker directive below embeds -rpath entries for target/release and
// target/debug so `go test ./...` works out of the box. Set
// PII_SHIELD_LIB_PATH (runtime, via LD_LIBRARY_PATH/`ld`-style loader
// configurators) or CGO_LDFLAGS for other locations.
package piishield

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/pii-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lpii_ffi
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/release
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdlib.h>
#include "pii_shield.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// TokenFormat selects the token style produced by redaction.
type TokenFormat int

const (
	TokenSequential      TokenFormat = 0
	TokenCompactHash     TokenFormat = 1
	TokenStatelessSealed TokenFormat = 2
)

// ToolTrustLevel controls the ACL applied to tool-call rehydration.
type ToolTrustLevel int

const (
	InternalTrusted   ToolTrustLevel = 0
	ExternalUntrusted ToolTrustLevel = 1
)

// ExfiltrationError is returned when an untrusted tool attempts to
// rehydrate PII. Token holds the offending vault token.
type ExfiltrationError struct {
	Token string
}

func (e *ExfiltrationError) Error() string {
	return fmt.Sprintf("PII exfiltration blocked: %s", e.Token)
}

// Vault is a thread-safe session vault handle built over PiiVaultHandle.
// The underlying RwLock allows concurrent read-only operations
// (Rehydrate, ExportSealedState, stream pushes) from multiple goroutines.
type Vault struct {
	handle *C.struct_PiiVaultHandle
}

func cString(s string) *C.char { return C.CString(s) }

// takeCString reads a returned *C.char into a Go string and frees the Rust
// heap allocation.
func takeCString(ptr *C.char) (string, error) {
	if ptr == nil {
		return "", fmt.Errorf("pii-shield: native call failed")
	}
	defer C.pii_string_free(ptr)
	return strings.Clone(goString(ptr)), nil
}

func goString(p *C.char) string { return C.GoString(p) }

// NewVault creates a vault with default locales ("global,id") and a
// freshly generated CSPRNG session key.
func NewVault() (*Vault, error) {
	h := C.pii_vault_new()
	if h == nil {
		return nil, fmt.Errorf("pii-shield: vault allocation failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// NewVaultWithLocales creates a vault restricted to the given locales CSV
// (e.g. "global,id,us"). Invalid locale names fail closed.
func NewVaultWithLocales(localesCSV string) (*Vault, error) {
	cs := cString(localesCSV)
	defer C.free(unsafe.Pointer(cs))
	h := C.pii_vault_new_with_locales(cs)
	if h == nil {
		return nil, fmt.Errorf("pii-shield: invalid locales %q", localesCSV)
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// NewVaultWithKey creates a vault with an explicit 32-byte shared key.
func NewVaultWithKey(localesCSV string, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pii-shield: key must be exactly 32 bytes, got %d", len(key))
	}
	var locales *C.char = nil
	if localesCSV != "" {
		locales = cString(localesCSV)
		defer C.free(unsafe.Pointer(locales))
	}
	h := C.pii_vault_new_with_locales_and_key(locales, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	if h == nil {
		return nil, fmt.Errorf("pii-shield: vault creation failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// NewVaultWithCustomTOML merges extra runtime TOML rules on top of the
// built-in locales. With a nil key a CSPRNG key is generated. Any TOML or
// regex validation error fails closed with an error.
func NewVaultWithCustomTOML(localesCSV string, customTOML string, key []byte) (*Vault, error) {
	var locales *C.char = nil
	if localesCSV != "" {
		locales = cString(localesCSV)
		defer C.free(unsafe.Pointer(locales))
	}
	tomlStr := cString(customTOML)
	defer C.free(unsafe.Pointer(tomlStr))

	var keyPtr *C.uint8_t
	var keyLen int
	if len(key) == 0 {
		keyPtr, keyLen = nil, 0
	} else {
		if len(key) != 32 {
			return nil, fmt.Errorf("pii-shield: key must be empty or exactly 32 bytes, got %d", len(key))
		}
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
		keyLen = len(key)
	}
	h := C.pii_vault_with_custom_toml(locales, tomlStr, keyPtr, C.size_t(keyLen))
	if h == nil {
		return nil, fmt.Errorf("pii-shield: invalid TOML rules or key; vault not created")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// Close releases the native vault. Close is idempotent.
func (v *Vault) Close() {
	if v == nil || v.handle == nil {
		return
	}
	C.pii_vault_free(v.handle)
	v.handle = nil
}

// SetTokenFormat configures the emitted token style.
func (v *Vault) SetTokenFormat(f TokenFormat) {
	C.pii_vault_set_token_format(v.handle, C.uint8_t(f))
}

// SetStatelessMode toggles the stateless (sealed) token mode.
func (v *Vault) SetStatelessMode(enabled bool) {
	C.pii_vault_set_stateless_mode(v.handle, C.bool(enabled))
}

// Redact replaces detected PII in free-form text with reversible tokens.
func (v *Vault) Redact(input string) (string, error) {
	cs := cString(input)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_redact(v.handle, cs))
}

// RedactJSON redacts string values of a JSON payload, leaving structure and
// numbers untouched.
func (v *Vault) RedactJSON(payload string) (string, error) {
	cs := cString(payload)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_redact_json(v.handle, cs))
}

// Rehydrate restores original values from tokens produced by this key
// cluster. Concurrency-safe (read-locked).
func (v *Vault) Rehydrate(input string) (string, error) {
	cs := cString(input)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_rehydrate(v.handle, cs))
}

// RehydrateForTool enforces tool ACLs; untrusted consumers are blocked and
// the returned error carries the offending token.
func (v *Vault) RehydrateForTool(payload string, trusted ToolTrustLevel) (string, error) {
	var errOut *C.char
	cs := cString(payload)
	defer C.free(unsafe.Pointer(cs))
	res := C.pii_vault_rehydrate_for_tool_ex(v.handle, cs, C.bool(trusted == InternalTrusted), &errOut)
	if res == nil {
		if errOut != nil {
			tok := goString(errOut)
			C.pii_string_free(errOut)
			return "", &ExfiltrationError{Token: tok}
		}
		return "", &ExfiltrationError{Token: "<UNKNOWN>"}
	}
	return takeCString(res)
}

// ExportSealedEntriesJSON exports all sealed entries for cross-vault import.
func (v *Vault) ExportSealedEntriesJSON(aad string) (string, error) {
	cs := cString(aad)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_export_sealed_entries_json(v.handle, cs))
}

// DrainDirtySealedEntriesJSON exports and clears pending unsealed entries.
func (v *Vault) DrainDirtySealedEntriesJSON(aad string) (string, error) {
	cs := cString(aad)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_drain_dirty_sealed_entries_json(v.handle, cs))
}

// ImportSealedEntriesJSON imports an entry map exported by a peer vault.
func (v *Vault) ImportSealedEntriesJSON(jsonMap string, aad string) error {
	cs := cString(jsonMap)
	defer C.free(unsafe.Pointer(cs))
	cAad := cString(aad)
	defer C.free(unsafe.Pointer(cAad))
	if !C.pii_vault_import_sealed_entries_json(v.handle, cs, cAad) {
		return fmt.Errorf("pii-shield: failed to import sealed entries")
	}
	return nil
}

// ExportSealedState serializes the whole vault state.
func (v *Vault) ExportSealedState(aad string) (string, error) {
	cs := cString(aad)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_vault_export_sealed_state(v.handle, cs))
}

// ImportSealedState restores a previously exported state blob.
func (v *Vault) ImportSealedState(sealed string, aad string) error {
	cs := cString(sealed)
	defer C.free(unsafe.Pointer(cs))
	cAad := cString(aad)
	defer C.free(unsafe.Pointer(cAad))
	if !C.pii_vault_import_sealed_state(v.handle, cs, cAad) {
		return fmt.Errorf("pii-shield: failed to import sealed state")
	}
	return nil
}

// StreamRehydrator rehydrates vault tokens split across SSE chunks,
// including tokens spanning chunk boundaries.
type StreamRehydrator struct {
	handle *C.struct_PiiStreamHandle
}

func NewStreamRehydrator() (*StreamRehydrator, error) {
	h := C.pii_stream_new()
	if h == nil {
		return nil, fmt.Errorf("pii-shield: stream allocation failed")
	}
	s := &StreamRehydrator{handle: h}
	runtime.SetFinalizer(s, (*StreamRehydrator).Close)
	return s, nil
}

func (s *StreamRehydrator) Close() {
	if s == nil || s.handle == nil {
		return
	}
	C.pii_stream_free(s.handle)
	s.handle = nil
}

func (s *StreamRehydrator) PushChunk(v *Vault, chunk string) (string, error) {
	cs := cString(chunk)
	defer C.free(unsafe.Pointer(cs))
	return takeCString(C.pii_stream_push_chunk(s.handle, v.handle, cs))
}

func (s *StreamRehydrator) Flush(v *Vault) (string, error) {
	return takeCString(C.pii_stream_flush(s.handle, v.handle))
}
