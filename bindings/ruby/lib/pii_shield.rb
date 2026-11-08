# frozen_string_literal: true

require "ffi"
require "singleton"

# Ruby SDK for pii-shield (libpii_ffi C-ABI).
#
# Memory-safety contract:
# * String-returning C functions are declared with return_type :pointer (NOT
#   :string) so the raw pointer stays visible; values are read via
#   `read_string` and the pointer is passed to pii_string_free inside an
#   `ensure` block.
# * Vault and stream handles use FFI::AutoPointer so pii_vault_free /
#   pii_stream_free run exactly once at GC time (unless `close`d eagerly).
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
        # Search workspace target/{release,debug}, walking up from this file.
        filename_dup = filename
          # bindings/ruby/lib -> workspace root is three levels up.
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
    attach_function :pii_vault_import_sealed_entries_json, %i[pointer string string], :bool
    attach_function :pii_vault_export_sealed_state, %i[pointer string], :pointer
    attach_function :pii_vault_import_sealed_state, %i[pointer string string], :bool

    # ---- streaming ---------------------------------------------------------------
    attach_function :pii_stream_new, [], :pointer
    attach_function :pii_stream_push_chunk, %i[pointer pointer string], :pointer
    attach_function :pii_stream_flush, %i[pointer pointer], :pointer
    attach_function :pii_stream_free, [:pointer], :void

    attach_function :pii_string_free, [:pointer], :void

    # Reads a returned *char into a UTF-8 Ruby string and frees the Rust buffer.
    def self.take_string(ptr)
      return nil if ptr.null?

      s = ptr.read_string.force_encoding(Encoding::UTF_8)
      protocol_string_free(ptr)
      s
    end

    def self.protocol_string_free(ptr)
      pii_string_free(ptr)
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

  # Immutable wrapper so FFI::AutoPointer owns the native vault lifetime.
  class Vault
    def initialize(locales_csv: nil, custom_toml: nil, key: nil)
      if custom_toml
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

    # Eagerly frees native resources. Safe to call multiple times.
    def close
      return unless @ptr

      @ptr.free
      @ptr = nil
    end

    def closed?
      @ptr.nil?
    end

    def handle
      raise "vault closed" if closed?

      @ptr
    end

    def set_token_format(fmt)
      FFILib.pii_vault_set_token_format(handle, fmt)
      nil
    end

    def set_stateless_mode(enabled)
      FFILib.pii_vault_set_stateless_mode(handle, enabled)
      nil
    end

    def redact(text)
      FFILib.take_string(FFILib.pii_vault_redact(handle, text))
    end

    def redact_json(payload)
      FFILib.take_string(FFILib.pii_vault_redact_json(handle, payload))
    end

    def rehydrate(text)
      FFILib.take_string(FFILib.pii_vault_rehydrate(handle, text))
    end

    # Rehydrates a tool-call payload. Raises ExfiltrationBlockedError (with the
    # exact offending token) when the tool is untrusted.
    def rehydrate_for_tool(payload, trusted:)
      err_ptr = FFI::MemoryPointer.new(:pointer)
      is_trusted = trusted == ToolTrustLevel::INTERNAL_TRUSTED || trusted == true
      out = FFILib.pii_vault_rehydrate_for_tool_ex(handle, payload, is_trusted, err_ptr)
      if out.null?
        token_ptr = err_ptr.read_pointer
        token = token_ptr.null? ? "<UNKNOWN>" : FFILib.take_string(token_ptr)
        raise ExfiltrationBlockedError.new(token)
      end
      FFILib.take_string(out)
    ensure
      err_ptr&.free
    end

    def export_sealed_entries_json(aad)
      FFILib.take_string(FFILib.pii_vault_export_sealed_entries_json(handle, aad))
    end

    def drain_dirty_sealed_entries_json(aad)
      FFILib.take_string(FFILib.pii_vault_drain_dirty_sealed_entries_json(handle, aad))
    end

    def import_sealed_entries_json(json_map, aad)
      raise ArgumentError, "failed to import sealed entries" unless FFILib.pii_vault_import_sealed_entries_json(handle, json_map, aad)
    end

    def export_sealed_state(aad)
      FFILib.take_string(FFILib.pii_vault_export_sealed_state(handle, aad))
    end

    def import_sealed_state(sealed, aad)
      raise ArgumentError, "failed to import sealed state" unless FFILib.pii_vault_import_sealed_state(handle, sealed, aad)
    end
  end

  # Rehydrates tokens split across streamed chunks (SSE).
  class StreamingRehydrator
    def initialize
      ptr = FFILib.pii_stream_new
      raise "stream allocation failed" if ptr.null?

      @ptr = FFI::AutoPointer.new(ptr, FFILib.method(:pii_stream_free))
    end

    def close
      return unless @ptr

      @ptr.free
      @ptr = nil
    end

    def handle
      raise "stream closed" if @ptr.nil?

      @ptr
    end

    def push_chunk(chunk, vault)
      FFILib.take_string(FFILib.pii_stream_push_chunk(handle, vault.handle, chunk))
    end

    def flush(vault)
      FFILib.take_string(FFILib.pii_stream_flush(handle, vault.handle))
    end
  end
end
