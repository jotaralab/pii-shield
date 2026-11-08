defmodule PiiShield do
  @moduledoc """
  Idiomatic Elixir SDK for pii-shield.
  """

  defmodule Error do
    defexception [:message, :token]

    @impl true
    def message(%{message: msg}), do: msg
  end

  @type vault :: reference()
  @type stream :: reference()
  @type trust :: :trusted | :untrusted

  # --------------------------------------------------------------------------
  # Lifecycle
  # --------------------------------------------------------------------------

  @doc "Creates a vault with default locales (global,id) and a CSPRNG key."
  @spec vault_new!() :: vault()
  def vault_new! do
    case PiiShield.Nif.vault_new() do
      {:ok, vault} -> vault
      {:error, _} -> raise Error, message: "vault allocation failed"
    end
  end

  @doc "Creates a vault for a comma-separated locales CSV. Fails closed on unknown locales."
  @spec vault_new!(String.t()) :: vault()
  def vault_new!(locales_csv) when is_binary(locales_csv) do
    case PiiShield.Nif.vault_new_with_locales(locales_csv) do
      {:ok, vault} -> vault
      {:error, _} -> raise Error, message: "invalid locales: #{inspect(locales_csv)}"
    end
  end

  @doc "Creates a vault with a 32-byte key and an optional locales CSV."
  @spec vault_new!(String.t() | nil, <<_::256>>) :: vault()
  def vault_new!(locales_csv, key) do
    case PiiShield.Nif.vault_new_with_key(locales_csv || "", key) do
      {:ok, vault} -> vault
      {:error, _} -> raise Error, message: "vault creation failed"
    end
  end

  @doc "Creates a vault merging custom TOML rules. `key` may be `nil` (CSPRNG)."
  @spec vault_new_with_custom_toml!(String.t() | nil, String.t(), <<_::256>> | nil) :: vault()
  def vault_new_with_custom_toml!(locales_csv, custom_toml, key \\ nil) do
    case PiiShield.Nif.vault_with_custom_toml(locales_csv || :undefined, custom_toml, key || :undefined) do
      {:ok, vault} -> vault
      {:error, _} ->
        raise Error, message: "invalid locales, TOML rules, or key"
    end
  end

  # --------------------------------------------------------------------------
  # Configuration
  # --------------------------------------------------------------------------

  @doc "Sets the token format: 0=Sequential, 1=CompactHash, 2=StatelessSealed."
  @spec set_token_format!(vault(), 0 | 1 | 2) :: :ok
  def set_token_format!(vault, fmt) do
    :ok = PiiShield.Nif.vault_set_token_format(vault, fmt)
    :ok
  end

  @doc "Toggles stateless (sealed) mode."
  @spec set_stateless_mode!(vault(), boolean()) :: :ok
  def set_stateless_mode!(vault, enabled) do
    :ok = PiiShield.Nif.vault_set_stateless_mode(vault, if(enabled, do: 1, else: 0))
    :ok
  end

  # --------------------------------------------------------------------------
  # Redaction / rehydration
  # --------------------------------------------------------------------------

  @doc "Redacts free-form text."
  @spec redact(vault(), String.t()) :: String.t()
  def redact(vault, text) do
    {:ok, out} = PiiShield.Nif.vault_redact(vault, :erlang.iolist_to_binary(text))
    out
  end

  @doc "Redacts string values inside a JSON payload."
  @spec redact_json(vault(), String.t()) :: String.t()
  def redact_json(vault, payload) do
    {:ok, out} = PiiShield.Nif.vault_redact_json(vault, :erlang.iolist_to_binary(payload))
    out
  end

  @doc "Rehydrates tokens on this vault back into raw values."
  @spec rehydrate(vault(), String.t()) :: String.t()
  def rehydrate(vault, text) do
    {:ok, out} = PiiShield.Nif.vault_rehydrate(vault, :erlang.iolist_to_binary(text))
    out
  end

  @doc """
  Rehydrates a tool-call payload after enforcing ACLs. Raises
  `PiiShield.Error` with `token:` set when exfiltration was blocked.
  """
  @spec rehydrate_for_tool!(vault(), String.t(), trust()) :: String.t()
  def rehydrate_for_tool!(vault, payload, trust) when trust in [:trusted, :untrusted] do
    case PiiShield.Nif.vault_rehydrate_for_tool(vault, :erlang.iolist_to_binary(payload), trust) do
      {:ok, out} -> out
      {:error, {:exfiltration_blocked, {:token, token}}} ->
        raise Error, message: "PII exfiltration blocked: #{token}", token: token
      {:error, _} ->
        raise Error, message: "vault error"
    end
  end

  # --------------------------------------------------------------------------
  # Streaming
  # --------------------------------------------------------------------------

  @doc "Creates a new streaming rehydrator."
  @spec stream_new!() :: stream()
  def stream_new! do
    {:ok, stream} = PiiShield.Nif.stream_new()
    stream
  end

  @doc "Pushes an SSE chunk through the streaming rehydrator."
  @spec stream_push_chunk(stream(), vault(), String.t()) :: String.t()
  def stream_push_chunk(stream, vault, chunk) do
    {:ok, out} = PiiShield.Nif.stream_push_chunk(stream, vault, :erlang.iolist_to_binary(chunk))
    out
  end

  @doc "Flushes the streaming rehydrator at end-of-stream."
  @spec stream_flush(stream(), vault()) :: String.t()
  def stream_flush(stream, vault) do
    {:ok, out} = PiiShield.Nif.stream_flush(stream, vault)
    out
  end
end
