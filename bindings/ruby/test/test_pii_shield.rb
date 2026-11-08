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

  def skip_unless_native
    unless File.exist?(
      File.expand_path(File.join(__dir__, "..", "..", "..", "target", "debug", "libpii_ffi.so"))
    ) || ENV["PII_SHIELD_LIB_PATH"]
      omit("shared library not built (run `cargo build -p pii-ffi`)")
    end
  end

  def test_redact_rehydrate_roundtrip
    skip_unless_native
    vault = PiiShield::Vault.new
    assert_not_equal 0, vault.handle
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
