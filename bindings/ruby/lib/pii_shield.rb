# frozen_string_literal: true

require "ffi"

# Ruby SDK for pii-shield (libpii_ffi C-ABI).
#
# Memory-safety contract:
# * String-returning C functions are declared with return_type :pointer (NOT
#   :string) so the raw pointer stays visible; values are read via
#   `read_string` and the pointer is passed to pii_string_free inside an
#   `ensure` block.
# * Vault and stream handles use FFI::AutoPointer so pii_vault_free /
#   pii_stream_free run exactly once at GC time (unless `close`d eagerly).
#   A per-instance Mutex prevents `close` from freeing the pointer while
#   another thread is inside a GVL-released FFI call.
module PiiShield
  module FFILib
    extend FFI::Library

    filename = case RUBY_PLATFORM
               when /mswin|mingw/ then "pii_ffi.dll"
               when /darwin/ then "libpii_ffi.dylib"
               else "libpii_ffi.so"
               end

    lib_path =
      if (env = ENV["PII_SHIELD_LIB_PATH"]) && !env.empty?
        if File.exist?(env)
          env
        else
          raise LoadError, "PII_SHIELD_LIB_PATH=#{env.inspect} does not exist"
        end
      else
        # Search workspace target/{release,debug}: bindings/ruby/lib -> the
        # cargo workspace root is three levels up from this file.
        filename_dup = filename
        root = File.expand_path("../../..", __dir__)
        candidates = [
          File.join(root, "target", "release", filename_dup),
          File.join(root, "target", "debug", filename_dup)
        ]
        candidates.find { |p| File.exist?(p) } || filename_dup
      end

    ffi_lib lib_path

    # ---- vault lifecycle -------------------------------------------------------
    attach_function :pii_vault_new, [], :pointer
    attach_function :pii_vault_new_with_locales, [:string], :pointer
    attach_function :pii_vault_new_with_key, %i[uint8 pointer size_t], :pointer
    attach_function(
      :pii_vault_new_with_locales_and_key,
      %i[string pointer size_t],
      :pointer
    )
    attach_function(
      :pii_vault_with_custom_toml,
      %i[string string pointer size_t],
      :pointer
    )
    attach_function :pii_vault_free, [:pointer], :void
    attach_function :pii_vault_set_token_format, %i[pointer uint8], :void
    attach_function :pii_vault_set_stateless_mode, %i[pointer bool], :void
    attach_function :pii_vault_is_stateless_mode, [:pointer], :bool

    # ---- redaction / rehydration ------------------------------------------------
    # NOTE: return_type must be :pointer, never :string, so the returned Rust
    # heap pointer can be freed with pii_string_free (leak prevention).
    attach_function :pii_vault_redact, %i[pointer string], :pointer
    attach_function :pii_vault_redact_json, %i[pointer string], :pointer
    attach_function :pii_vault_rehydrate, %i[pointer string], :pointer
    attach_function :pii_vault_rehydrate_for_tool, %i[pointer string bool], :pointer
    attach_function(
      :pii_vault_rehydrate_for_tool_ex,
      %i[pointer string bool pointer],
      :pointer
    )

    # ---- persistence -----------------------------------------------------------
    attach_function :pii_vault_export_sealed_entries_json, %i[pointer string], :pointer
    attach_function :pii_vault_drain_dirty_sealed_entries_json, %i[pointer string], :pointer
    attach_function(
      :pii_vault_seal_dirty_sealed_entries_json,
      %i[pointer string],
      :pointer
    )
    attach_function(
      :pii_vault_clear_dirty_tokens,
      %i[pointer string],
      :bool
    )
    attach_function :pii_vault_import_sealed_entries_json, %i[pointer string string], :bool
    attach_function :pii_vault_export_sealed_state, %i[pointer string], :pointer
    attach_function :pii_vault_import_sealed_state, %i[pointer string string], :bool

    # ---- streaming ---------------------------------------------------------------
    attach_function :pii_stream_new, [], :pointer
    attach_function :pii_stream_push_chunk, %i[pointer pointer string], :pointer
    attach_function :pii_stream_flush, %i[pointer pointer], :pointer
    attach_function :pii_stream_free, [:pointer], :void

    attach_function :pii_string_free, [:pointer], :void

    # Reads a returned *char into a UTF-8 Ruby string. The Rust buffer is
    # freed inside `ensure` so even if `read_string` raises (e.g. an
    # unexpected encoding failure), the native allocation never leaks.
    def self.take_string(ptr)
      return nil if ptr.nil? || ptr.null?

      begin
        ptr.read_string.force_encoding(Encoding::UTF_8)
      ensure
        pii_string_free(ptr)
      end
    end
  end

  # Raised when an untrusted tool attempts to rehydrate PII. `token` holds the
  # exact offending vault token reported by pii_vault_rehydrate_for_tool_ex.
  class ExfiltrationBlockedError < StandardError
    attr_reader :token

    def initialize(token)
      @token = token
      super("PII exfiltration blocked: #{token}")
    end
  end

  # Token styles produced by redaction.
  module TokenFormat
    SEQUENTIAL = 0
    COMPACT_HASH = 1
    STATELESS_SEALED = 2
  end

  # Tool trust levels for ACL-enforced rehydration.
  module ToolTrustLevel
    INTERNAL_TRUSTED = true
    EXTERNAL_UNTRUSTED = false
  end

  # Validates that a string argument crosses the FFI boundary intact: valid
  # UTF-8, no interior NUL bytes. Interior NUL would silently truncate the
  # argument; invalid UTF-8 would fail closed inside the engine.
  def self.validate_cstring!(value, name)
    raise ArgumentError, "#{name} must be a String, got #{value.class}" unless value.is_a?(String)
    raise ArgumentError, "#{name} must be valid UTF-8" unless value.valid_encoding?
    raise ArgumentError, "#{name} must not contain interior NUL bytes" if value.include?("\0")

    value
  end

  # Wrapper over PiiVaultHandle with FFI::AutoPointer ownership.
  class Vault
    def initialize(locales_csv: nil, custom_toml: nil, key: nil)
      @mutex = Mutex.new
      key = key.dup.freeze if key
      locales_csv &&= PiiShield.validate_cstring!(locales_csv, "locales_csv")
      # An explicitly-supplied but empty/blank locales CSV fails closed
      # inside the engine; nil (not passed) selects the default "global,id".
      raise ArgumentError, "locales_csv must not be empty" if locales_csv.is_a?(String) && locales_csv.strip.empty?

      if custom_toml
        PiiShield.validate_cstring!(custom_toml, "custom_toml")
        key_ptr = nil
        key_len = 0
        if key
          raise ArgumentError, "key must be exactly 32 bytes" unless key.bytesize == 32

          key_buf = FFI::MemoryPointer.new(:uchar, 32)
          key_buf.write_bytes(key)
          key_ptr = key_buf
          key_len = 32
        end
        ptr = FFILib.pii_vault_with_custom_toml(
          locales_csv, custom_toml, key_ptr, key_len
        )
      elsif key
        raise ArgumentError, "key must be exactly 32 bytes" unless key.bytesize == 32

        buf = FFI::MemoryPointer.new(:uchar, 32)
        buf.write_bytes(key)
        ptr = FFILib.pii_vault_new_with_locales_and_key(locales_csv, buf, 32)
      else
        ptr = FFILib.pii_vault_new_with_locales(locales_csv)
      end

      raise ArgumentError, "vault creation failed (invalid locales, TOML rules, or key)" if ptr.null?

      @ptr = FFI::AutoPointer.new(ptr, FFILib.method(:pii_vault_free))
    end

    # Eagerly frees native resources. Safe to call multiple times and from
    # any thread; the mutex keeps close() from racing an in-flight FFI call
    # (FFI calls release the GVL).
    def close
      @mutex.synchronize do
        return unless @ptr

        @ptr.free
        @ptr = nil
      end
    end

    def closed?
      @mutex.synchronize { @ptr.nil? }
    end

    def handle
      with_handle { |h| h }
    end

    def with_handle
      @mutex.synchronize do
        raise "vault closed" if @ptr.nil?

        yield @ptr
      end
    end

    def set_token_format(fmt)
      raise ArgumentError, "fmt must be an Integer in 0..2" unless fmt.is_a?(Integer) && (0..2).cover?(fmt)

      with_handle { |h| FFILib.pii_vault_set_token_format(h, fmt) }
      nil
    end

    def set_stateless_mode(enabled)
      raise ArgumentError, "enabled must be true or false" unless enabled == true || enabled == false

      with_handle { |h| FFILib.pii_vault_set_stateless_mode(h, enabled) }
      nil
    end

    def is_stateless_mode?
      with_handle { |h| FFILib.pii_vault_is_stateless_mode(h) }
    end

    def redact(text)
      PiiShield.validate_cstring!(text, "text")
      with_handle { |h| result_or_fail(FFILib.take_string(FFILib.pii_vault_redact(h, text)), "redact") }
    end

    def redact_json(payload)
      PiiShield.validate_cstring!(payload, "payload")
      with_handle { |h| result_or_fail(FFILib.take_string(FFILib.pii_vault_redact_json(h, payload)), "redact_json") }
    end

    def rehydrate(text)
      PiiShield.validate_cstring!(text, "text")
      with_handle { |h| result_or_fail(FFILib.take_string(FFILib.pii_vault_rehydrate(h, text)), "rehydrate") }
    end

    # Rehydrates a tool-call payload. Only raises ExfiltrationBlockedError
    # (with the exact offending token) when the engine reports an ACL block
    # through err_out; any other failure raises RuntimeError.
    def rehydrate_for_tool(payload, trusted:)
      raise ArgumentError, "trusted must be true or false" unless trusted == true || trusted == false

      PiiShield.validate_cstring!(payload, "payload")
      is_trusted = trusted == ToolTrustLevel::INTERNAL_TRUSTED
      with_handle do |h|
        err_ptr = FFI::MemoryPointer.new(:pointer)
        out = FFILib.pii_vault_rehydrate_for_tool_ex(h, payload, is_trusted, err_ptr)
        if out.null?
          token_ptr = err_ptr.read_pointer
          unless token_ptr.null?
            token = FFILib.take_string(token_ptr)
            raise ExfiltrationBlockedError.new(token) if token

            raise "native rehydrate_for_tool_ex call failed"
          end
          raise "native rehydrate_for_tool_ex call failed"
        end
        result_or_fail(FFILib.take_string(out), "rehydrate_for_tool")
      ensure
        err_ptr&.free
      end
    end

    def export_sealed_entries_json(aad)
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        result_or_fail(
          FFILib.take_string(FFILib.pii_vault_export_sealed_entries_json(h, aad)),
          "export_sealed_entries_json"
        )
      end
    end

    def drain_dirty_sealed_entries_json(aad)
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        result_or_fail(
          FFILib.take_string(FFILib.pii_vault_drain_dirty_sealed_entries_json(h, aad)),
          "drain_dirty_sealed_entries_json"
        )
      end
    end

    # Two-phase sync, step 1: snapshot the dirty entries without clearing
    # them (non-destructive counterpart of drain_dirty_sealed_entries_json).
    def seal_dirty_sealed_entries_json(aad)
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        result_or_fail(
          FFILib.take_string(FFILib.pii_vault_seal_dirty_sealed_entries_json(h, aad)),
          "seal_dirty_sealed_entries_json"
        )
      end
    end

    # Two-phase sync, step 2: clear the given tokens after a successful
    # store write. Accepts the JSON array of tokens exported by the seal /
    # drain helpers, e.g. `["<ID_NIK_A1>"]`.
    def clear_dirty_tokens(tokens_json)
      PiiShield.validate_cstring!(tokens_json, "tokens_json")
      with_handle do |h|
        raise ArgumentError, "failed to clear dirty tokens" unless FFILib.pii_vault_clear_dirty_tokens(h, tokens_json)
      end

      nil
    end

    def import_sealed_entries_json(json_map, aad)
      PiiShield.validate_cstring!(json_map, "json_map")
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        raise ArgumentError, "failed to import sealed entries" unless FFILib.pii_vault_import_sealed_entries_json(h, json_map, aad)
      end
    end

    def export_sealed_state(aad)
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        result_or_fail(
          FFILib.take_string(FFILib.pii_vault_export_sealed_state(h, aad)),
          "export_sealed_state"
        )
      end
    end

    def import_sealed_state(sealed, aad)
      PiiShield.validate_cstring!(sealed, "sealed")
      PiiShield.validate_cstring!(aad, "aad")
      with_handle do |h|
        raise ArgumentError, "failed to import sealed state" unless FFILib.pii_vault_import_sealed_state(h, sealed, aad)
      end
    end

    private

    # A NULL return means the native call failed; never collapse that into
    # an empty (possibly empty-looking but valid) string.
    def result_or_fail(value, op)
      raise "native #{op} call failed" if value.nil?

      value
    end
  end

  # Rehydrates tokens split across streamed chunks (SSE).
  class StreamingRehydrator
    def initialize
      @mutex = Mutex.new
      ptr = FFILib.pii_stream_new
      raise "stream allocation failed" if ptr.null?

      @ptr = FFI::AutoPointer.new(ptr, FFILib.method(:pii_stream_free))
    end

    def close
      @mutex.synchronize do
        return unless @ptr

        @ptr.free
        @ptr = nil
      end
    end

    def closed?
      @mutex.synchronize { @ptr.nil? }
    end

    def handle
      with_handle { |h| h }
    end

    def with_handle
      @mutex.synchronize do
        raise "stream closed" if @ptr.nil?

        yield @ptr
      end
    end

    def push_chunk(chunk, vault)
      PiiShield.validate_cstring!(chunk, "chunk")
      with_handle do |sh|
        vault.with_handle do |vh|
          result_or_fail(
            FFILib.take_string(FFILib.pii_stream_push_chunk(sh, vh, chunk)),
            "push_chunk"
          )
        end
      end
    end

    def flush(vault)
      with_handle do |sh|
        vault.with_handle do |vh|
          result_or_fail(
            FFILib.take_string(FFILib.pii_stream_flush(sh, vh)),
            "flush"
          )
        end
      end
    end

    private

    def result_or_fail(value, op)
      raise "native #{op} call failed" if value.nil?

      value
    end
  end
end
