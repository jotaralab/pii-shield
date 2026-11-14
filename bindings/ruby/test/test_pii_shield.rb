# frozen_string_literal: true

# Ruby test suite for the pii_shield bindings.
#
# Run (from bindings/ruby, with libpii_ffi built at the workspace root):
#
#   gem install ffi --no-document
#   ruby -Ilib:test test/test_pii_shield.rb

require "test/unit"
require "json"
require "pii_shield"

class TestPiiShield < Test::Unit::TestCase
  CUSTOM_TOML = <<~TOML
    locale = "custom"
    name = "Custom"

    [[rules]]
    id = "CUSTOM_ACC"
    tag_prefix = "CUSTOM_ACC"
    regex = '\\bACC-[0-9]{6}\\b'
    validator = "none"
  TOML

  LIB_FILENAME =
    case RUBY_PLATFORM
    when /mswin|mingw/ then "pii_ffi.dll"
    when /darwin/ then "libpii_ffi.dylib"
    else "libpii_ffi.so"
    end

  def skip_unless_native
    built =
      %w[release debug].any? do |build|
        File.exist?(File.expand_path(File.join(__dir__, "..", "..", "..", "target", build, LIB_FILENAME)))
      end
    omit("shared library not built (run `cargo build -p pii-ffi`)") unless built || ENV["PII_SHIELD_LIB_PATH"]
  end

  def test_redact_rehydrate_roundtrip
    skip_unless_native
    vault = PiiShield::Vault.new
    refute_predicate vault, :closed?
    begin
      vault.set_token_format(PiiShield::TokenFormat::COMPACT_HASH)
      redacted = vault.redact("NIK 3573012203950001")
      assert_match(/<ID_NIK_/, redacted)
      assert_not_match(/3573012203950001/, redacted)
      assert_equal "NIK 3573012203950001", vault.rehydrate(redacted)
    ensure
      vault.close
    end
  end

  def test_unknown_locale_fails_closed
    skip_unless_native
    e = assert_raise(ArgumentError) { PiiShield::Vault.new(locales_csv: "global_typo") }
    assert_match(/creation failed/, e.message)
  end

  def test_empty_locales_fail_closed
    skip_unless_native
    assert_raise(ArgumentError) { PiiShield::Vault.new(locales_csv: "") }
    assert_raise(ArgumentError) { PiiShield::Vault.new(locales_csv: " , ") }
  end

  def test_bad_key_rejected
    skip_unless_native
    assert_raise(ArgumentError) do
      PiiShield::Vault.new(locales_csv: "global", key: "short")
    end
  end

  def test_custom_toml
    skip_unless_native
    vault = PiiShield::Vault.new(
      locales_csv: "global",
      custom_toml: CUSTOM_TOML,
      key: Array.new(32) { |i| (100 + i) }.pack("C*")
    )
    begin
      redacted = vault.redact("Account ACC-123456 opened")
      assert_match(/<CUSTOM_ACC_/, redacted)
      assert_equal "Account ACC-123456 opened", vault.rehydrate(redacted)
    ensure
      vault.close
    end
  end

  def test_exfiltration_blocked_reports_token
    skip_unless_native
    vault = PiiShield::Vault.new
    begin
      redacted = vault.redact("NIK 3573012203950001")
      e = assert_raise(PiiShield::ExfiltrationBlockedError) do
        vault.rehydrate_for_tool(redacted, trusted: PiiShield::ToolTrustLevel::EXTERNAL_UNTRUSTED)
      end
      assert_match(/^</, e.token)

      trusted = vault.rehydrate_for_tool(redacted, trusted: PiiShield::ToolTrustLevel::INTERNAL_TRUSTED)
      assert_match(/3573012203950001/, trusted)
    ensure
      vault.close
    end
  end

  def test_invalid_trust_rejected
    skip_unless_native
    vault = PiiShield::Vault.new
    begin
      assert_raise(ArgumentError) do
        vault.rehydrate_for_tool("x", trusted: "yes")
      end
      assert_raise(ArgumentError) do
        vault.rehydrate_for_tool("x", trusted: 1)
      end
    ensure
      vault.close
    end
  end

  def test_nul_and_invalid_utf8_rejected
    skip_unless_native
    vault = PiiShield::Vault.new
    begin
      assert_raise(ArgumentError) { vault.redact("a\x00b") }
      assert_raise(ArgumentError) { vault.rehydrate("\x00") }
      assert_raise(ArgumentError) { vault.import_sealed_entries_json("{\x00}", "aad") }
      assert_raise(ArgumentError) { vault.import_sealed_entries_json("{}", "aad\x00") }
      assert_raise(ArgumentError) { vault.import_sealed_state("PIIS1:\x00", "aad") }
      assert_raise(ArgumentError) { vault.import_sealed_state("PIIS1:AA", "aad\x00") }
      bad = String.new("caf\xC3".b)
      bad.force_encoding(Encoding::UTF_8)
      assert_raise(ArgumentError) { vault.redact(bad) }
      assert_raise(ArgumentError) { vault.import_sealed_entries_json(bad, "aad") }
      assert_raise(ArgumentError) { vault.import_sealed_state(bad, "aad") }
    ensure
      vault.close
    end
  end

  def test_closed_vault_raises
    skip_unless_native
    vault = PiiShield::Vault.new
    vault.close
    assert_predicate vault, :closed?
    vault.close # idempotent
    assert_raise(RuntimeError) { vault.redact("x") }
    assert_raise(RuntimeError) { vault.handle }
  end

  def test_redact_json_preserves_numbers
    skip_unless_native
    vault = PiiShield::Vault.new
    begin
      redacted = vault.redact_json('{"nik":"3573012203950001","order_id":1234567890123456}')
      parsed = JSON.parse(redacted)
      assert_equal 1_234_567_890_123_456, parsed["order_id"]
      assert parsed["nik"].start_with?("<ID_NIK_")
    ensure
      vault.close
    end
  end

  def test_two_phase_seal_clear_and_stateless
    skip_unless_native
    vault = PiiShield::Vault.new
    begin
      vault.set_token_format(PiiShield::TokenFormat::COMPACT_HASH)
      vault.redact("NIK 3573012203950001")
      sealed = vault.seal_dirty_sealed_entries_json("aad:ruby")
      refute_empty JSON.parse(sealed)

      tokens = JSON.parse(sealed).keys
      vault.clear_dirty_tokens(JSON.generate(tokens))
      assert_equal({}, JSON.parse(vault.seal_dirty_sealed_entries_json("aad:ruby")))

      vault.set_token_format(PiiShield::TokenFormat::STATELESS_SEALED)
      assert vault.is_stateless_mode?
      vault.set_token_format(PiiShield::TokenFormat::SEQUENTIAL)
      refute vault.is_stateless_mode?
    ensure
      vault.close
    end
  end

  def test_sealed_entries_cross_vault
    skip_unless_native
    key = Array.new(32) { |i| i }.pack("C*")
    v1 = PiiShield::Vault.new(locales_csv: "global,id", key: key)
    v2 = PiiShield::Vault.new(locales_csv: "global,id", key: key)
    begin
      v1.set_token_format(PiiShield::TokenFormat::COMPACT_HASH)
      redacted = v1.redact("NIK 3573012203950001")
      dirty = v1.drain_dirty_sealed_entries_json("session:rubytest")
      refute_empty JSON.parse(dirty)
      v2.import_sealed_entries_json(dirty, "session:rubytest")
      assert_equal "NIK 3573012203950001", v2.rehydrate(redacted)
    ensure
      v1.close
      v2.close
    end
  end

  def test_streaming_rehydrator_split_token
    skip_unless_native
    vault = PiiShield::Vault.new
    stream = PiiShield::StreamingRehydrator.new
    begin
      redacted = vault.redact("NIK 3573012203950001")
      half = redacted.length / 2
      out = stream.push_chunk(redacted[0, half], vault)
      out += stream.push_chunk(redacted[half..], vault)
      out += stream.flush(vault)
      assert_equal "NIK 3573012203950001", out
    ensure
      stream.close
      vault.close
    end
  end
end
