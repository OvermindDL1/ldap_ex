# LDAPEx

This is a fairly direct port of the Erlang :eldap  module to Elixir, but using
pure strings/binaries instead of char_lists like :eldap does.  Will add
additional features and modules over time.

## Installation

If [available in Hex](https://hex.pm/docs/publish) (not yet), the package can be installed as:

  1. Add `:ldap_ex` to your list of dependencies in `mix.exs`:

     ```elixir
     def deps do
     [{:ldap_ex, "~> 0.0.1"}]
     end
     ```

  2. If you want defaults (highly recommended) for any unspecified value, add
     something like this to your configuration:

     ```elixir
     config :ldap_ex, :defaults, %{
         server: System.get_env("LDAP_SERVER"),
         port: elem(Integer.parse(System.get_env("LDAP_PORT")), 0),
         ssl: System.get_env("LDAP_SSL") == "true"
         username: System.get_env("LDAP_USERNAME"),
         password: System.get_env("LDAP_PASSWORD"),
         timeout: 5
       }
     ```
