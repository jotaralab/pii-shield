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

  @doc "Creates a vault for a comma-separated locales CSV. Fails closed on unknown or empty locales."
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
    case PiiShield.Nif.vault_new_with_key(locales_csv || :undefined, key) do
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
  def set_token_format!(vault, fmt) when fmt in [0, 1, 2] do
    :ok = PiiShield.Nif.vault_set_token_format(vault, fmt)
    :ok
  end

  @doc "Toggles stateless (sealed) mode."
  @spec set_stateless_mode!(vault(), boolean()) :: :ok
  def set_stateless_mode!(vault, enabled) when is_boolean(enabled) do
    :ok = PiiShield.Nif.vault_set_stateless_mode(vault, if(enabled, do: 1, else: 0))
    :ok
  end

  @doc "Whether the vault is currently in stateless sealed-token mode."
  @spec stateless_mode?(vault()) :: boolean()
  def stateless_mode?(vault) do
    PiiShield.Nif.vault_is_stateless_mode(vault)
  end

  # --------------------------------------------------------------------------
  # Redaction / rehydration
  # --------------------------------------------------------------------------

  @doc "Redacts free-form text."
  @spec redact(vault(), String.t()) :: String.t()
  def redact(vault, text) do
    case PiiShield.Nif.vault_redact(vault, to_bin(text)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "redact failed: #{inspect(reason)}"
    end
  end

  @doc "Redacts string values inside a JSON payload."
  @spec redact_json(vault(), String.t()) :: String.t()
  def redact_json(vault, payload) do
    case PiiShield.Nif.vault_redact_json(vault, to_bin(payload)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "redact_json failed: #{inspect(reason)}"
    end
  end

  @doc "Rehydrates tokens on this vault back into raw values."
  @spec rehydrate(vault(), String.t()) :: String.t()
  def rehydrate(vault, text) do
    case PiiShield.Nif.vault_rehydrate(vault, to_bin(text)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "rehydrate failed: #{inspect(reason)}"
    end
  end

  @doc """
  Rehydrates a tool-call payload after enforcing ACLs. Raises
  `PiiShield.Error` with `token:` set when exfiltration was blocked.
  """
  @spec rehydrate_for_tool!(vault(), String.t(), trust()) :: String.t()
  def rehydrate_for_tool!(vault, payload, trust) when trust in [:trusted, :untrusted] do
    case PiiShield.Nif.vault_rehydrate_for_tool(vault, to_bin(payload), trust) do
      {:ok, out} -> out
      {:error, {:exfiltration_blocked, {:token, token}}} ->
        raise Error, message: "PII exfiltration blocked: #{token}", token: token
      {:error, reason} ->
        raise Error, message: "vault error: #{inspect(reason)}"
    end
  end

  # --------------------------------------------------------------------------
  # Sealed-state & dirty-token persistence
  # --------------------------------------------------------------------------

  @doc "Exports all sealed entries (JSON map token -> sealed blob) for cross-vault import."
  @spec export_sealed_entries_json(vault(), String.t()) :: String.t()
  def export_sealed_entries_json(vault, aad \\ "") do
    case PiiShield.Nif.vault_export_sealed_entries_json(vault, to_bin(aad)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "export_sealed_entries_json failed: #{inspect(reason)}"
    end
  end

  @doc "Exports and clears pending dirty entries (JSON map) since the last sync."
  @spec drain_dirty_sealed_entries_json(vault(), String.t()) :: String.t()
  def drain_dirty_sealed_entries_json(vault, aad \\ "") do
    case PiiShield.Nif.vault_drain_dirty_sealed_entries_json(vault, to_bin(aad)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "drain_dirty_sealed_entries_json failed: #{inspect(reason)}"
    end
  end

  @doc """
  Non-destructive counterpart of `drain_dirty_sealed_entries_json/2`:
  snapshots the dirty entries without clearing them (safe to use while a
  store write is in flight). Pair with `clear_dirty_tokens!/2` afterwards.
  """
  @spec seal_dirty_sealed_entries_json(vault(), String.t()) :: String.t()
  def seal_dirty_sealed_entries_json(vault, aad \\ "") do
    case PiiShield.Nif.vault_seal_dirty_sealed_entries_json(vault, to_bin(aad)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "seal_dirty_sealed_entries_json failed: #{inspect(reason)}"
    end
  end

  @doc ~S'Clears the given tokens (JSON array, e.g. `["<ID_NIK_A1>"]`) from the dirty set.'
  @spec clear_dirty_tokens!(vault(), String.t()) :: :ok
  def clear_dirty_tokens!(vault, tokens_json) do
    if PiiShield.Nif.vault_clear_dirty_tokens(vault, to_bin(tokens_json)) do
      :ok
    else
      raise Error, message: "failed to clear dirty tokens"
    end
  end

  @doc "Imports an entries map exported by a peer vault sharing the same key."
  @spec import_sealed_entries_json!(vault(), String.t(), String.t()) :: :ok
  def import_sealed_entries_json!(vault, json_map, aad \\ "") do
    if PiiShield.Nif.vault_import_sealed_entries_json(vault, to_bin(json_map), to_bin(aad)) do
      :ok
    else
      raise Error, message: "failed to import sealed entries"
    end
  end

  @doc "Exports the whole vault state as a sealed blob."
  @spec export_sealed_state(vault(), String.t()) :: String.t()
  def export_sealed_state(vault, aad \\ "") do
    case PiiShield.Nif.vault_export_sealed_state(vault, to_bin(aad)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "export_sealed_state failed: #{inspect(reason)}"
    end
  end

  @doc "Restores a sealed-state blob exported by a peer vault."
  @spec import_sealed_state!(vault(), String.t(), String.t()) :: :ok
  def import_sealed_state!(vault, sealed, aad \\ "") do
    if PiiShield.Nif.vault_import_sealed_state(vault, to_bin(sealed), to_bin(aad)) do
      :ok
    else
      raise Error, message: "failed to import sealed state"
    end
  end

  # --------------------------------------------------------------------------
  # Streaming
  # --------------------------------------------------------------------------

  @doc "Creates a new streaming rehydrator."
  @spec stream_new!() :: stream()
  def stream_new! do
    case PiiShield.Nif.stream_new() do
      {:ok, stream} -> stream
      {:error, _} -> raise Error, message: "stream allocation failed"
    end
  end

  @doc "Pushes an SSE chunk through the streaming rehydrator."
  @spec stream_push_chunk(stream(), vault(), String.t()) :: String.t()
  def stream_push_chunk(stream, vault, chunk) do
    case PiiShield.Nif.stream_push_chunk(stream, vault, to_bin(chunk)) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "stream_push_chunk failed: #{inspect(reason)}"
    end
  end

  @doc "Flushes the streaming rehydrator at end-of-stream."
  @spec stream_flush(stream(), vault()) :: String.t()
  def stream_flush(stream, vault) do
    case PiiShield.Nif.stream_flush(stream, vault) do
      {:ok, out} -> out
      {:error, reason} -> raise Error, message: "stream_flush failed: #{inspect(reason)}"
    end
  end

  defp to_bin(text) when is_binary(text), do: text
  defp to_bin(text) when is_list(text), do: :erlang.iolist_to_binary(text)
end
