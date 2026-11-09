defmodule PiiShield.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :pii_shield,
      version: @version,
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      description:
        "Sub-millisecond PII redaction & reversible pseudonymization for AI agents (Elixir NIF bindings).",
      package: package(),
      compilers: [:pii_nif] ++ Mix.compilers(),
      docs: []
    ]
  end

  defp package do
    [
      maintainers: ["Jotara Lab"],
      licenses: ["Apache-2.0", "MIT"],
      links: %{"GitHub" => "https://github.com/jotaralab/pii-shield"},
      files: ~w(lib c_src mix.exs README.md)
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end
end

defmodule Mix.Tasks.Compile.PiiNif do
  @moduledoc """
  Compiles `c_src/pii_shield_nif.c` (the Erlang NIF shim) and links it
  against `libpii_ffi`.

  Environment:
    * `PII_SHIELD_LIB_PATH` – path to libpii_ffi.{so,dylib} or pii_ffi.dll.
      Defaults to the workspace `target/{release,debug}` directories.
    * `ERL_NIF_INCLUDE` – directory containing `erl_nif.h`
      (e.g. `/usr/lib/erlang/usr/include`, via `erl -eval 'io:format("~s~n",[code:root_dir()])'`).
  """
  use Mix.Task

  @lib_names ["libpii_ffi.so", "libpii_ffi.dylib", "pii_ffi.dll"]

  @impl true
  def run(_args) do
    priv = Path.join(Mix.Project.app_path(), "priv")
    priv_nif = Path.join(priv, "pii_shield_nif.so")
    File.mkdir_p!(priv)

    lib = find_pii_ffi() || raise(RuntimeError, """
    Could not find libpii_ffi. Build the shared library from the workspace root:

        cargo build -p pii-ffi

    or set PII_SHIELD_LIB_PATH=/absolute/path/to/libpii_ffi.so
    """)

    lib = Path.expand(lib)
    priv_dir = Path.dirname(priv_nif)
    File.mkdir_p!(priv_dir)

    include_nif =
      System.get_env(
        "ERL_NIF_INCLUDE",
        Path.join(to_string(:code.root_dir()), "usr/include")
      )
    include_hdr = Path.expand("../../crates/pii-ffi/include", __ENV__.file |> Path.dirname())

    lib_dir = Path.dirname(lib)

    # macOS needs -dynamiclib (with undefined lookups resolved at load time
    # from the rpath-loaded libpii_ffi); Linux/other unix use -shared.
    base_flags =
      case :os.type() do
        {:unix, :darwin} -> ["-O2", "-fPIC", "-dynamiclib", "-undefined", "dynamic_lookup"]
        _ -> ["-O2", "-fPIC", "-shared"]
      end

    rpaths = ["-Wl,-rpath,#{lib_dir}"]
    rpaths =
      case :os.type() do
        # ld on macOS uses -rpath (no -Wl wrapper needed)
        {:unix, :darwin} -> for d <- rpaths, do: String.replace(d, "-Wl,-rpath,", "-rpath,")
        _ -> rpaths
      end

    args =
      files_for(Path.join(File.cwd!(), "c_src/pii_shield_nif.c")) ++
        base_flags ++
        ["-I#{include_nif}", "-I#{include_hdr}", "-L#{lib_dir}"] ++
        rpaths ++
        ["-lpii_ffi", "-o", priv_nif]

    env = %{"CC" => System.get_env("CC", "cc")}

    {output, status} = System.cmd(env["CC"], args, env: env)

    if status != 0, do: Mix.raise("pii_shield_nif compile failed:\n#{output}")
    Mix.shell().info("Compiled pii_shield_nif -> #{priv_nif}")
    :ok
  end

  defp files_for(source), do: [source]

  defp find_pii_ffi do
    case System.get_env("PII_SHIELD_LIB_PATH") do
      p when is_binary(p) and p != "" -> if File.exists?(p), do: p
      _ ->
        Enum.find_value(@lib_names, fn name ->
          Enum.find_value(["release", "debug"], fn build ->
            path = Path.join([File.cwd!(), "..", "..", "target", build, name])
            if File.exists?(path), do: path
          end)
        end)
    end
  end
end
