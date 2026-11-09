// Package piishield provides idiomatic Go bindings for pii-shield, the
// sub-millisecond PII redaction & reversible pseudonymization engine.
//
// The package wraps the C-ABI of libpii_ffi via cgo. All functions returning
// C strings are freed with C.pii_string_free (input C.CString allocations are
// freed with C.free) so no Rust heap memory leaks. Handle lifecycles are
// synchronized: Close cannot race an in-flight call, and every method
// validates the handle under the lock so use-after-Close returns
// ErrVaultClosed instead of undefined behavior.
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
#cgo !windows LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/release
#cgo !windows LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdlib.h>
#include "pii_shield.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"
)

// ErrVaultClosed is returned by operations on an already-closed Vault or
// StreamRehydrator.
var ErrVaultClosed = errors.New("pii-shield: handle is closed")

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
// The native handle sits behind an RwLock: read-only operations
// (Rehydrate, ExportSealedState, stream pushes) run concurrently while
// Close takes an exclusive lock.
type Vault struct {
	mu     sync.RWMutex
	handle *C.struct_PiiVaultHandle
}

// cString validates and encodes a Go string as a C string. Interior NUL
// bytes would silently truncate the argument at the FFI boundary, and
// invalid UTF-8 would fail closed inside the engine, so both are rejected
// up front with a descriptive error.
func cString(s string) (*C.char, error) {
	if strings.IndexByte(s, 0) != -1 {
		return nil, fmt.Errorf("pii-shield: string must not contain interior NUL bytes")
	}
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("pii-shield: string must be valid UTF-8")
	}
	return C.CString(s), nil
}

// takeCString reads a returned *C.char into a Go string and frees the Rust
// heap allocation.
func takeCString(ptr *C.char) (string, error) {
	if ptr == nil {
		return "", fmt.Errorf("pii-shield: native call failed")
	}
	defer C.pii_string_free(ptr)
	return goString(ptr), nil
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
// (e.g. "global,id,us"). Invalid locale names fail closed; an empty string
// fails closed as well (pass NewVault for the default locale set).
func NewVaultWithLocales(localesCSV string) (*Vault, error) {
	cs, err := cString(localesCSV)
	if err != nil {
		return nil, fmt.Errorf("pii-shield: locales: %w", err)
	}
	defer C.free(unsafe.Pointer(cs))
	h := C.pii_vault_new_with_locales(cs)
	if h == nil {
		return nil, fmt.Errorf("pii-shield: invalid locales %q", localesCSV)
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// NewVaultWithKey creates a vault with an explicit 32-byte shared key. An
// empty localesCSV selects the default ("global,id") locale set.
func NewVaultWithKey(localesCSV string, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pii-shield: key must be exactly 32 bytes, got %d", len(key))
	}
	var locales *C.char = nil
	if localesCSV != "" {
		cs, err := cString(localesCSV)
		if err != nil {
			return nil, fmt.Errorf("pii-shield: locales: %w", err)
		}
		defer C.free(unsafe.Pointer(cs))
		locales = cs
	}
	h := C.pii_vault_new_with_locales_and_key(locales, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if h == nil {
		return nil, fmt.Errorf("pii-shield: vault creation failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// NewVaultWithCustomTOML merges extra runtime TOML rules on top of the
// built-in locales. A nil key generates a CSPRNG session key; a
// non-nil key must be exactly 32 bytes. Any TOML or regex validation error
// fails closed with an error.
func NewVaultWithCustomTOML(localesCSV string, customTOML string, key []byte) (*Vault, error) {
	var locales *C.char = nil
	if localesCSV != "" {
		cs, err := cString(localesCSV)
		if err != nil {
			return nil, fmt.Errorf("pii-shield: locales: %w", err)
		}
		defer C.free(unsafe.Pointer(cs))
		locales = cs
	}
	tomlStr, err := cString(customTOML)
	if err != nil {
		return nil, fmt.Errorf("pii-shield: custom TOML: %w", err)
	}
	defer C.free(unsafe.Pointer(tomlStr))

	var keyPtr *C.uint8_t
	var keyLen int
	if key == nil {
		keyPtr, keyLen = nil, 0
	} else {
		if len(key) != 32 {
			return nil, fmt.Errorf("pii-shield: key must be nil or exactly 32 bytes, got %d", len(key))
		}
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
		keyLen = len(key)
	}
	h := C.pii_vault_with_custom_toml(locales, tomlStr, keyPtr, C.size_t(keyLen))
	runtime.KeepAlive(key)
	if h == nil {
		return nil, fmt.Errorf("pii-shield: invalid TOML rules or key; vault not created")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, (*Vault).Close)
	return v, nil
}

// Close releases the native vault. Close is idempotent and safe for
// concurrent use.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.handle == nil {
		return
	}
	runtime.SetFinalizer(v, nil)
	C.pii_vault_free(v.handle)
	v.handle = nil
}

func (v *Vault) locked() (*C.struct_PiiVaultHandle, error) {
	v.mu.RLock()
	if v == nil || v.handle == nil {
		v.mu.RUnlock()
		return nil, ErrVaultClosed
	}
	return v.handle, nil
}

// SetTokenFormat configures the emitted token style.
func (v *Vault) SetTokenFormat(f TokenFormat) error {
	h, err := v.locked()
	if err != nil {
		return err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	C.pii_vault_set_token_format(h, C.uint8_t(f))
	return nil
}

// SetStatelessMode toggles the stateless (sealed) token mode.
func (v *Vault) SetStatelessMode(enabled bool) error {
	h, err := v.locked()
	if err != nil {
		return err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	C.pii_vault_set_stateless_mode(h, C.bool(enabled))
	return nil
}

// IsStatelessMode reports whether the vault is currently in stateless
// sealed-token mode.
func (v *Vault) IsStatelessMode() (bool, error) {
	h, err := v.locked()
	if err != nil {
		return false, err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return bool(C.pii_vault_is_stateless_mode(h)), nil
}

// Redact replaces detected PII in free-form text with reversible tokens.
func (v *Vault) Redact(input string) (string, error) {
	cs, err := cString(input)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_redact(h, cs))
}

// RedactJSON redacts string values of a JSON payload, leaving structure and
// numbers untouched.
func (v *Vault) RedactJSON(payload string) (string, error) {
	cs, err := cString(payload)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_redact_json(h, cs))
}

// Rehydrate restores original values from tokens produced by this key
// cluster. Concurrency-safe (read-locked).
func (v *Vault) Rehydrate(input string) (string, error) {
	cs, err := cString(input)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_rehydrate(h, cs))
}

// RehydrateForTool enforces tool ACLs; untrusted consumers are blocked and
// the returned error carries the offending token. Non-ACL failures (e.g. a
// native operational error) surface as a plain error.
func (v *Vault) RehydrateForTool(payload string, trusted ToolTrustLevel) (string, error) {
	cs, err := cString(payload)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	var errOut *C.char
	res := C.pii_vault_rehydrate_for_tool_ex(h, cs, C.bool(trusted == InternalTrusted), &errOut)
	if res == nil {
		if errOut != nil {
			tok := goString(errOut)
			C.pii_string_free(errOut)
			return "", &ExfiltrationError{Token: tok}
		}
		return "", fmt.Errorf("pii-shield: rehydrate_for_tool failed")
	}
	return takeCString(res)
}

// ExportSealedEntriesJSON exports all sealed entries for cross-vault import.
func (v *Vault) ExportSealedEntriesJSON(aad string) (string, error) {
	cs, err := cString(aad)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_export_sealed_entries_json(h, cs))
}

// DrainDirtySealedEntriesJSON exports and clears pending unsealed entries.
func (v *Vault) DrainDirtySealedEntriesJSON(aad string) (string, error) {
	cs, err := cString(aad)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_drain_dirty_sealed_entries_json(h, cs))
}

// SealDirtySealedEntriesJSON snapshots the dirty entries without clearing
// them: safe to use while a store write is in flight (two-phase sync, step
// 1). Call ClearDirtyTokens after the write succeeds.
func (v *Vault) SealDirtySealedEntriesJSON(aad string) (string, error) {
	cs, err := cString(aad)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_seal_dirty_sealed_entries_json(h, cs))
}

// ClearDirtyTokens removes the given tokens from the dirty set after a
// successful store write (two-phase sync, step 2). tokens is the JSON array
// produced by SealDirtySealedEntriesJSON / DrainDirtySealedEntriesJSON
// tokens, e.g. `["<ID_NIK_A1>"]`.
func (v *Vault) ClearDirtyTokens(tokensJSON string) error {
	cs, err := cString(tokensJSON)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	if !C.pii_vault_clear_dirty_tokens(h, cs) {
		return fmt.Errorf("pii-shield: failed to clear dirty tokens")
	}
	return nil
}

// ImportSealedEntriesJSON imports an entry map exported by a peer vault.
func (v *Vault) ImportSealedEntriesJSON(jsonMap string, aad string) error {
	cs, err := cString(jsonMap)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cs))
	cAad, err := cString(aad)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cAad))
	h, err := v.locked()
	if err != nil {
		return err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	if !C.pii_vault_import_sealed_entries_json(h, cs, cAad) {
		return fmt.Errorf("pii-shield: failed to import sealed entries")
	}
	return nil
}

// ExportSealedState serializes the whole vault state.
func (v *Vault) ExportSealedState(aad string) (string, error) {
	cs, err := cString(aad)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_vault_export_sealed_state(h, cs))
}

// ImportSealedState restores a previously exported state blob.
func (v *Vault) ImportSealedState(sealed string, aad string) error {
	cs, err := cString(sealed)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cs))
	cAad, err := cString(aad)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cAad))
	h, err := v.locked()
	if err != nil {
		return err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	if !C.pii_vault_import_sealed_state(h, cs, cAad) {
		return fmt.Errorf("pii-shield: failed to import sealed state")
	}
	return nil
}

// StreamRehydrator rehydrates vault tokens split across SSE chunks,
// including tokens spanning chunk boundaries.
type StreamRehydrator struct {
	mu     sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return
	}
	runtime.SetFinalizer(s, nil)
	C.pii_stream_free(s.handle)
	s.handle = nil
}

func (s *StreamRehydrator) PushChunk(v *Vault, chunk string) (string, error) {
	cs, err := cString(chunk)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cs))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return "", ErrVaultClosed
	}
	defer runtime.KeepAlive(s)
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_stream_push_chunk(s.handle, h, cs))
}

func (s *StreamRehydrator) Flush(v *Vault) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return "", ErrVaultClosed
	}
	defer runtime.KeepAlive(s)
	h, err := v.locked()
	if err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	defer runtime.KeepAlive(v)
	return takeCString(C.pii_stream_flush(s.handle, h))
}
