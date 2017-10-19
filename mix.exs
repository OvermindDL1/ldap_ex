defmodule LDAPEx.Mixfile do
  use Mix.Project

  @description """
    This is a binary instead of char_list version of the stock Erlang :eldap library.
  """

  def project do
    [ app: :ldap_ex,
      version: "0.2.4",
      description: @description,
      package: package(),
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      erlc_paths: ["lib/asn1"],
      source_url: "https://github.com/OvermindDL1/ldap_ex",
      #homepage_url: "http://YOUR_PROJECT_HOMEPAGE",
      docs: [
        #logo: "path/to/logo.png",
        extras: ["README.md": [path: "getting_started", title: "Getting Started"]],
        main: "getting_started"
      ],
      deps: deps()]
  end

  defp package do
    [ licenses: ["MIT"],
      name: :ldap_ex,
      maintainers: ["OvermindDL1"],
      links: %{"Github" => "https://github.com/OvermindDL1/ldap_ex"} ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger, :asn1, :ssl],
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
    [{:credo, "~> 0.8", only: [:dev]},
     {:dialyxir, "~> 0.5", only: [:dev]},
     {:earmark, "~> 1.2", only: [:dev]},
     {:ex_doc, "~> 0.18", only: [:dev]}
    ]
  end
end
