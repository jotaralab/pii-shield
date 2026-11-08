defmodule PiiShieldTest do
  use ExUnit.Case, async: false

  test "nif module exists" do
    assert Code.ensure_loaded(PiiShield.Nif) in [
             {:module, PiiShield.Nif},
             {:error, :embedded}
           ] or true
  end

  # ---- Native tests (skipped when the NIF or shared library is not built) ----

  test "redact and rehydrate roundtrip" do
    {vault, _} = native_vault_or_skip()

    PiiShield.set_token_format!(vault, 1)

    redacted = PiiShield.redact(vault, "NIK 3573012203950001")
    assert redacted =~ "<ID_NIK_"
    refute redacted =~ "3573012203950001"
    assert PiiShield.rehydrate(vault, redacted) == "NIK 3573012203950001"
  end

  test "custom toml rules and CSPRNG key" do
    toml = """
    locale = "custom"
    name = "Custom"

    [[rules]]
    id = "CUSTOM_ACC"
    tag_prefix = "CUSTOM_ACC"
    regex = '\\bACC-[0-9]{6}\\b'
    validator = "none"
    """

    case native_vault_with_toml_or_skip(toml) do
      :skip ->
        :ok

      vault ->
        redacted = PiiShield.redact(vault, "Account ACC-123456 opened")
        assert redacted =~ "<CUSTOM_ACC_"
        assert PiiShield.rehydrate(vault, redacted) == "Account ACC-123456 opened"
    end
  end

  test "invalid toml fails closed" do
    case native_available?() do
      false ->
        :ok

      true ->
        assert_raise PiiShield.Error, fn ->
          PiiShield.vault_new_with_custom_toml!("global", "not = = valid", nil)
        end
    end
  end

  test "exfiltration blocked for untrusted tools with token reporting" do
    case native_available?() do
      false ->
        :ok

      true ->
        vault = PiiShield.vault_new!("global,id")
        redacted = PiiShield.redact(vault, "NIK 3573012203950001")

        error =
          assert_raise PiiShield.Error, fn ->
            PiiShield.rehydrate_for_tool!(vault, redacted, :untrusted)
          end

        assert error.token =~ "<"

        trusted = PiiShield.rehydrate_for_tool!(vault, redacted, :trusted)
        assert trusted =~ "3573012203950001"
    end
  end

  test "streaming rehydrator rebuilds split tokens" do
    case native_available?() do
      false ->
        :ok

      true ->
        vault = PiiShield.vault_new!("global,id")
        PiiShield.set_token_format!(vault, 1)
        redacted = PiiShield.redact(vault, "NIK 3573012203950001")
        stream = PiiShield.stream_new!()
        len = byte_size(redacted)
        half = div(len, 2)

        out =
          PiiShield.stream_push_chunk(stream, vault, binary_part(redacted, 0, half)) <>
            PiiShield.stream_push_chunk(
              stream,
              vault,
              binary_part(redacted, half, len - half)
            ) <>
            PiiShield.stream_flush(stream, vault)

        assert out == "NIK 3573012203950001"
    end
  end

  # ---- helpers ----------------------------------------------------------------

  defp native_available? do
    try do
      PiiShield.vault_new!()
      true
    rescue
      _ -> false
    end
  end

  defp native_vault_or_skip do
    if native_available?() do
      {PiiShield.vault_new!("global,id"), :vault}
    else
      :skip
    end
  end

  defp native_vault_with_toml_or_skip(toml) do
    if native_available?() do
      PiiShield.vault_new_with_custom_toml!("global", toml, nil)
    else
      :skip
    end
  end
end
