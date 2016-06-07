defmodule LDAPEx.Mixfile do
  use Mix.Project

  @description """
    This is a binary instead of char_list version of the stock Erlang :eldap library.
  """

  def project do
    [app: :ldap_ex,
     version: "0.0.1",
     description: @description,
     package: package,
     elixir: "~> 1.2",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  defp package do
    [ licenses: ["MIT"],
      name: :ldap_ex,
      maintainers: ["Gabriel Robertson"],
      links: %{"Github" => "https://github.com/OvermindDL1/LDAPEx"} ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger],
     mod: {LDAPEx, []}]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [{:credo, "~> 0.3", only: [:dev, :test]},
     {:dialyxir, "~> 0.3", only: [:dev]}]
  end
end
