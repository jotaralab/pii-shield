defmodule PiiShield.Nif do
  @moduledoc """
  Thin FFI shim: loads `priv/pii_shield_nif.so`, which wraps `libpii_ffi`.

  Each function here is a stub that the loaded NIF replaces at `load_nif`
  time. Stubs fail loudly with `erlang:nif_error/1` before the NIF loads.
  """

  @nifs [
    vault_new: 0,
    vault_new_with_locales: 1,
    vault_new_with_key: 2,
    vault_with_custom_toml: 3,
    vault_set_token_format: 2,
    vault_set_stateless_mode: 2,
    vault_redact: 2,
    vault_redact_json: 2,
    vault_rehydrate: 2,
    vault_rehydrate_for_tool: 3,
    stream_new: 0,
    stream_push_chunk: 3,
    stream_flush: 2
  ]

  @on_load {:load_nif, 0}

  def load_nif do
    priv_dir =
      case :code.priv_dir(:pii_shield) do
        # during mix compile the app path may not be on the code path yet
        {:error, _} -> Path.join([File.cwd!(), "_build", "dev", "lib", "pii_shield", "priv"])
        dir -> dir
      end

    path = :filename.join(priv_dir, String.to_charlist("pii_shield_nif"))

    case :erlang.load_nif(path, 0) do
      :ok ->
        :ok

      {:error, {:reload, _}} ->
        :ok

      {:error, reason} ->
        raise """
        Failed to load PiiShield NIF (#{inspect(reason)}).

        Build the Rust shared library and the NIF shim:

            cargo build -p pii-ffi     # from the workspace root
            mix compile                # inside bindings/elixir

        Or point PII_SHIELD_LIB_PATH at an existing libpii_ffi.{so,dylib}.
        """
    end
  end

  # ---- stubs (replaced by the NIF at load time) -------------------------------

  @spec vault_new() :: {:ok, reference()} | {:error, atom()}
  def vault_new, do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_new_with_locales(String.t()) :: {:ok, reference()} | {:error, atom()}
  def vault_new_with_locales(_locales_csv), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_new_with_key(String.t(), binary()) :: {:ok, reference()} | {:error, atom()}
  def vault_new_with_key(_locales_csv, _key), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_with_custom_toml(term(), binary(), binary()) :: {:ok, reference()} | {:error, atom()}
  def vault_with_custom_toml(_locales_csv, _custom_toml, _key),
    do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_set_token_format(reference(), integer()) :: :ok
  def vault_set_token_format(_vault, _fmt), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_set_stateless_mode(reference(), integer()) :: :ok
  def vault_set_stateless_mode(_vault, _enabled), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_redact(reference(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def vault_redact(_vault, _text), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_redact_json(reference(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def vault_redact_json(_vault, _payload), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_rehydrate(reference(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def vault_rehydrate(_vault, _text), do: :erlang.nif_error(:nif_not_loaded)

  @spec vault_rehydrate_for_tool(reference(), binary(), atom()) ::
          {:ok, String.t()} | {:error, {:exfiltration_blocked, {:token, String.t()}}} | {:error, atom()}
  def vault_rehydrate_for_tool(_vault, _payload, _trust), do: :erlang.nif_error(:nif_not_loaded)

  @spec stream_new() :: {:ok, reference()} | {:error, atom()}
  def stream_new, do: :erlang.nif_error(:nif_not_loaded)

  @spec stream_push_chunk(reference(), reference(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def stream_push_chunk(_stream, _vault, _chunk), do: :erlang.nif_error(:nif_not_loaded)

  @spec stream_flush(reference(), reference()) :: {:ok, String.t()} | {:error, atom()}
  def stream_flush(_stream, _vault), do: :erlang.nif_error(:nif_not_loaded)
end
