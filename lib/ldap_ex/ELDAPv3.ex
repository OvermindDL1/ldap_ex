defmodule LDAPEx.ELDAPv3 do
  @moduledoc """
  This is the module to the Erlang generated LDAP interfaces from the LDAP ASN1
  file.  The macros are records.  `LDAPEx.ELDAPv3.encode/2` and
  `LDAPEx.ELDAPv3.decode/2` call into the erlang generated encode and decode
  functions.  Everything is set up to take binaries instead of char_lists.
  """

  require Record
  import Record, only: [defrecord: 2, extract_all: 1, is_record: 2]


  for rec <- extract_all(from: "lib/asn1/ELDAPv3a.hrl") do
    defrecord elem(rec, 0), elem(rec, 1)
  end


  def encode(type, data) do
    :ELDAPv3a.encode(type, data)
  end


  def decode(type, data) do
    :ELDAPv3a.decode(type, data)
  end

end
