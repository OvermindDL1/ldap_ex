# LDAPEx

This is a fairly direct port of the Erlang :eldap  module to Elixir, but using
pure strings/binaries instead of char_lists like :eldap does.  Will add
additional features and modules over time.

## Installation

[Available in Hex](https://hex.pm/packages/ldap_ex), the package can be
installed by:

  1. Add `:ldap_ex` to your list of dependencies in `mix.exs`:

     ```elixir
     def deps do
     [{:ldap_ex, "~> 0.1.0"}]
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

## Features

Thus far this is good for reading from LDAP, it has no writing functionality as
of yet, though it should be fairly simple to add now that the complex handling
is complete.  Pull Requests are welcome and encouraged.

As of right now it is mostly feature-complete for what I am needing, however I
may add a DSEL, perhaps ecto-like for the complex search request record.  May
eventually add a LDAPEx.Ecto adapter for integration with ecto2.  Of course if
anyone wants to add any of these wanted features or anything else useful then
please submit Pull Requests.
