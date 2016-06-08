defmodule LDAPEx.Config do
  @moduledoc """
  This module handles reading in the default config from the environment while
  also combining those with any passed-in overrides.
  """

  #require Logger

  @defaults %{
      server: :server_undefined,
      port: 389,
      ssl: false,
      username: "",
      password: "",
      timeout: 5000
    }

  @doc """
  Returns the environment default configuration map

  ## Examples
  ```elixir

    iex> vals = LDAPEx.Config.get_config()
    iex> is_map(vals)
    true

  ```
  """
  def get_config() do
    Map.merge(@defaults, Application.get_env(:ldap_ex, :defaults, %{}))
  end

  @doc """
  Returns the environment default configuration map with overrides specified

  ## Examples
  ```elixir

    iex> vals = LDAPEx.Config.get_config(server: "127.0.0.1")
    iex> is_map(vals)
    true
    iex> vals.server
    "127.0.0.1"

    iex> vals = LDAPEx.Config.get_config(%{server: "127.0.0.1"})
    iex> is_map(vals)
    true
    iex> vals.server
    "127.0.0.1"

  ```
  """
  def get_config(overrides) when is_list(overrides) do
    Enum.into(overrides, get_config())
  end

  def get_config(overrides) when is_map(overrides) do
    Map.merge(get_config(), overrides)
  end

end
