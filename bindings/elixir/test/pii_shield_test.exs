defmodule PiiShieldTest do
  use ExUnit.Case, async: false

  @key :erlang.list_to_binary(Enum.to_list(0..31))

  test "nif module exists" do
    assert Code.ensure_loaded(PiiShield.Nif) in [
             {:module, PiiShield.Nif},
             {:error, :embedded}
           ]
  end

  # ---- Native tests (skipped when the NIF or shared library is not built) ----

  test "redact and rehydrate roundtrip" do
    case native_vault_or_skip() do
      :skip ->
        :ok

      vault ->
        PiiShield.set_token_format!(vault, 1)

        redacted = PiiShield.redact(vault, "NIK 3573012203950001")
        assert redacted =~ "<ID_NIK_"
        refute redacted =~ "3573012203950001"
        assert PiiShield.rehydrate(vault, redacted) == "NIK 3573012203950001"
    end
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

  test "empty locales fail closed instead of selecting defaults" do
    case native_available?() do
      false ->
        :ok

      true ->
        # The NIF rejects an empty locale payload with :badarg.
        assert_raise ArgumentError, fn -> PiiShield.vault_new!("") end
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

  test "sealed entries and state round-trip across vaults" do
    case native_available?() do
      false ->
        :ok

      true ->
        v1 = PiiShield.vault_new!("global,id", @key)
        v2 = PiiShield.vault_new!("global,id", @key)
        PiiShield.set_token_format!(v1, 1)
        redacted = PiiShield.redact(v1, "NIK 3573012203950001")

        # Seal (non-destructive) + clear dirty tokens.
        {:ok, sealed} = PiiShield.Nif.vault_seal_dirty_sealed_entries_json(v1, "aad:ex")
        # Fallback to the high-level API to double-check shape.
        sealed2 = PiiShield.seal_dirty_sealed_entries_json(v1, "aad:ex")
        assert sealed =~ "PIIE1:"
        assert labels(sealed) == labels(sealed2)

        tokens = tokens_json(sealed)
        assert :ok = PiiShield.clear_dirty_tokens!(v1, tokens)
        assert PiiShield.seal_dirty_sealed_entries_json(v1, "aad:ex") == "{}"

        # Cross-vault import + rehydrate.
        assert :ok = PiiShield.import_sealed_entries_json!(v2, sealed, "aad:ex")
        assert PiiShield.rehydrate(v2, redacted) == "NIK 3573012203950001"

        # Sealed-state roundtrip.
        state = PiiShield.export_sealed_state(v1, "aad:state")
        assert state =~ "PIIS1:"
        assert :ok = PiiShield.import_sealed_state!(v2, state, "aad:state")
        assert PiiShield.rehydrate(v2, redacted) == "NIK 3573012203950001"

        # stateless mode query
        PiiShield.set_stateless_mode!(v1, true)
        assert PiiShield.stateless_mode?(v1)
        PiiShield.set_stateless_mode!(v1, false)
        refute PiiShield.stateless_mode?(v1)
    end
  end

  test "nul bytes rejected" do
    case native_available?() do
      false ->
        :ok

      true ->
        vault = PiiShield.vault_new!("global,id")
        assert_raise ArgumentError, fn -> PiiShield.redact(vault, <<97, 0, 98>>) end
        assert_raise ArgumentError, fn ->
          PiiShield.rehydrate_for_tool!(vault, <<0>>, :trusted)
        end
    end
  end

  # ---- helpers ----------------------------------------------------------------

  defp labels(sealed_json) do
    sealed_json
    |> :json.decode()
    |> Map.keys()
    |> Enum.sort()
  end

  defp tokens_json(sealed_json) do
    sealed_json
    |> :json.decode()
    |> Map.keys()
    |> :json.encode()
  end

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
      PiiShield.vault_new!("global,id")
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
